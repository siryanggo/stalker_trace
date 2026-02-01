/* ========================================================================
 * Frida Stalker Trace Script (V6 - Final Fix)
 * 功能：指令级 Trace + 内存透视 + SIMD(q0-q15)读取 + 修复 sp 崩溃
 * ======================================================================== */

// --- 配置区域 ---
const CONFIG = {
    ENABLE_COLOR: true,
    STR_PEEK_LEN: 32,
    LOOP_THRESHOLD: 10
};

// --- CModule 源码 (无头文件依赖) ---
const cmSource = `
#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t x[29];   // x0 - x28
    uint64_t fp;      // x29
    uint64_t lr;      // x30
    uint64_t sp;      // sp
    uint64_t pc;      // pc
    uint8_t  v[32][16]; // v0 - v31
} MyArm64CpuContext;

void dump_simd_regs(void *ctx, void *user_data) {
    MyArm64CpuContext *cpu = (MyArm64CpuContext *)ctx;
    uint8_t *out_buffer = (uint8_t *)user_data;
    // 拷贝前 16 个向量寄存器 (q0-q15)
    for (int i = 0; i < 16; i++) {
        memcpy(out_buffer + (i * 16), cpu->v[i], 16);
    }
}
`;

// --- 初始化 CModule ---
let cm = null;
let simdBuffer = null;

try {
    cm = new CModule(cmSource);
    simdBuffer = Memory.alloc(16 * 16);
    console.log("[*] CModule 编译成功！SIMD 寄存器读取功能已就绪。");
} catch (e) {
    console.log("\x1b[31m[!] CModule 编译失败: " + e.message + "\x1b[0m");
}

// --- 颜色定义 ---
const C = CONFIG.ENABLE_COLOR ? {
    RESET: "\x1b[0m", RED: "\x1b[31m", GREEN: "\x1b[32m", YELLOW: "\x1b[33m",
    BLUE: "\x1b[34m", MAGENTA: "\x1b[35m", CYAN: "\x1b[36m", GRAY: "\x1b[90m"
} : { RESET: "", RED: "", GREEN: "", YELLOW: "", BLUE: "", MAGENTA: "", CYAN: "", GRAY: "" };

// --- 辅助函数 ---
function getModuleByAddressSafe(address) {
    try { return Process.getModuleByAddress(address); } catch (e) { return null; }
}

function isSafePointer(ptrVal) {
    if (!ptrVal || ptrVal.isNull()) return false;
    try {
        if (ptrVal.compare(0x10000) < 0) return false;
        if (ptrVal.and(7).toInt32() !== 0) return false;
    } catch(e) { return false; }
    return true;
}

function toHex128(ptrToData) {
    const ab = ptrToData.readByteArray(16);
    const u8 = new Uint8Array(ab);
    let hex = "";
    for(let i = 15; i >= 0; i--) {
        hex += u8[i].toString(16).padStart(2, '0');
    }
    return "0x" + hex;
}

// [关键修复] 获取寄存器值
function getRegisterValue(context, regName) {
    // 1. 优先处理 sp, wzr, xzr，防止 sp 误入 SIMD 逻辑
    if (regName === 'sp') return context.sp;
    if (regName === 'wzr' || regName === 'xzr') return ptr(0);

    // 2. 通用寄存器 x0-x28
    if (regName.startsWith('w')) {
        const xRegName = 'x' + regName.substring(1);
        return context[xRegName] ? context[xRegName].and(0xFFFFFFFF) : undefined;
    }

    // 3. SIMD 寄存器 (q, d, s, h, b)
    if (['q', 'd', 's', 'h', 'b'].some(p => regName.startsWith(p))) {
        if (!simdBuffer) return '(No-CModule)';
        
        // 安全正则：先获取 match 结果
        const match = regName.match(/\d+/);
        if (!match) return '?'; // 再次兜底，防止意外

        const regIndex = parseInt(match[0]);
        if (regIndex < 16) {
            const regPtr = simdBuffer.add(regIndex * 16);
            return toHex128(regPtr);
        }
        return '(SIMD-OOB)'; 
    }

    // 4. 默认 (x0, fp, lr, pc)
    return context[regName];
}

function inspectMemory(ptrVal) {
    if (!isSafePointer(ptrVal)) return ''; 
    try {
        const bytes = ptrVal.readByteArray(CONFIG.STR_PEEK_LEN);
        if (bytes) {
            const u8 = new Uint8Array(bytes);
            let isString = true, len = 0;
            for (let i = 0; i < u8.length; i++) {
                if (u8[i] === 0) break;
                if (u8[i] < 32 || u8[i] > 126) { isString = false; break; }
                len++;
            }
            if (isString && len > 2) return `${C.GREEN} => "${ptrVal.readUtf8String(len)}"${C.RESET}`;
        }
    } catch (e) {}
    
    try {
        const pointed = ptrVal.readPointer();
        if (isSafePointer(pointed)) return `${C.BLUE} => *(${pointed})${C.RESET}`;
    } catch (e) {}
    return '';
}

function formatOperandDetails(instruction, context) {
    const details = [];
    instruction.operands.forEach(op => {
        switch (op.type) {
            case 'reg':
                let val = getRegisterValue(context, op.value);
                if (val === undefined) val = '?';
                let extra = '';
                // 只有 x/sp 可能是指针，q 已经是 Hex 了
                if ((op.value.startsWith('x') || op.value === 'sp') && typeof val !== 'string') {
                    extra = inspectMemory(val);
                }
                details.push(`${C.MAGENTA}${op.value}${C.RESET}=${val}${extra}`);
                break;
            case 'mem':
                let memAddress = 'N/A', memContent = '';
                if (op.value.base) {
                    const baseValue = getRegisterValue(context, op.value.base);
                    if (baseValue && baseValue.add) {
                        const calculatedAddr = baseValue.add(op.value.disp);
                        memAddress = calculatedAddr.toString();
                        try {
                            let loadedVal = calculatedAddr.readPointer(); 
                            memContent = ` ${C.BLUE}[val=${loadedVal}]${C.RESET}`;
                            memContent += inspectMemory(loadedVal);
                        } catch(e) {}
                    }
                }
                details.push(`[${op.value.base}+${op.value.disp}]=${memAddress}${memContent}`);
                break;
            case 'imm':
                details.push(`${C.GREEN}#${op.value}${C.RESET}`);
                break;
        }
    });
    return details.length > 0 ? `(${details.join(', ')})` : '';
}

function getDiffRegisters(context, lastRegs) {
    const GENERAL_REGS = ['x0', 'x1', 'x2', 'x3', 'x8', 'fp', 'lr', 'sp'];
    const changed = [];
    for (const regName of GENERAL_REGS) {
        const val = context[regName];
        const newValue = val.toString();
        if (lastRegs[regName] !== newValue) {
            changed.push(`${regName}=${newValue}`);
        }
        lastRegs[regName] = newValue;
    }
    return changed.length > 0 ? ` | { ${C.RED}${changed.join(', ')}${C.RESET} }` : '';
}

function trace(targetModuleName, targetOffset) {
    const base = Module.findBaseAddress(targetModuleName);
    if (!base) return console.error(`[!] 模块 ${targetModuleName} 未加载`);
    const targetFuncAddr = base.add(targetOffset);

    console.log(`\n🎯 开启 Trace (Final): ${targetModuleName} + ${targetOffset}`);
    console.log(`   📍 地址: ${targetFuncAddr}\n`);

    Interceptor.attach(targetFuncAddr, {
        onEnter(args) {
            this.tid = Process.getCurrentThreadId();
            this.lastRegs = {};
            this.lastInstructionLog = null;
            this.loopCounter = {};

            console.log(`${C.YELLOW}[tid: ${this.tid}] >>>>> 进入函数 >>>>>${C.RESET}`);

            Stalker.follow(this.tid, {
                events: { exec: true },
                transform: (iterator) => {
                    let instruction = iterator.next();
                    const stalkerCtx = this;

                    do {
                        const module = getModuleByAddressSafe(instruction.address);
                        if (module && module.name === targetModuleName) {
                            
                            // 1. C Callout
                            if (cm) iterator.putCallout(cm.dump_simd_regs, simdBuffer);

                            // 2. JS Callout
                            iterator.putCallout(context => {
                                const pcKey = context.pc.toString();
                                if (!stalkerCtx.loopCounter[pcKey]) stalkerCtx.loopCounter[pcKey] = 0;
                                stalkerCtx.loopCounter[pcKey]++;
                                if (stalkerCtx.loopCounter[pcKey] > CONFIG.LOOP_THRESHOLD && stalkerCtx.loopCounter[pcKey] % 100 !== 0) return;

                                const diff = getDiffRegisters(context, stalkerCtx.lastRegs);
                                if (stalkerCtx.lastInstructionLog) console.log(stalkerCtx.lastInstructionLog + diff);

                                const currentInstr = Instruction.parse(context.pc);
                                const offset = ptr(context.pc).sub(module.base);
                                const operandDetails = formatOperandDetails(currentInstr, context);

                                let color = C.CYAN;
                                if (currentInstr.mnemonic.startsWith('bl')) color = C.YELLOW;
                                if (currentInstr.mnemonic.startsWith('ret')) color = C.RED;

                                stalkerCtx.lastInstructionLog =
                                    `${C.GRAY}[${offset}]${C.RESET} ` +
                                    `${currentInstr.address} ` +
                                    `${color}${currentInstr.mnemonic.padEnd(8)}${C.RESET} ` +
                                    `${currentInstr.opStr.padEnd(30)} ` +
                                    `${operandDetails.padEnd(40)}`; 
                            });
                        }
                        iterator.keep();
                    } while ((instruction = iterator.next()) !== null);
                },
            });
        },
        onLeave(retval) {
            Stalker.flush(this.tid);
            Stalker.unfollow(this.tid);
            if (this.lastInstructionLog) console.log(this.lastInstructionLog);
            console.log(`${C.YELLOW}\n<<<<< 结束 (Ret=${retval}) <<<<<${C.RESET}\n`);
        }
    });
}

setImmediate(() => {
    // ⬇️⬇️ 请修改此处 ⬇️⬇️
    const TARGET_MODULE = "libnative-lib.so";
    const TARGET_OFFSET = 0xa3c; 
    // ⬆️⬆️ 请修改此处 ⬆️⬆️
    
    const int_check = setInterval(() => {
        if (Module.findBaseAddress(TARGET_MODULE)) {
            clearInterval(int_check);
            trace(TARGET_MODULE, TARGET_OFFSET);
        }
    }, 500);
});