// These AMI DXE/SMM images combine mutable firmware globals with code in .text.
// The PE section flags alone would let the decompiler fold zero-initialized
// service pointers into constants (and even interpret MZ at address zero).
// Set analysis permissions only; original PE files are not modified.
// @category Firmware.X99
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
public class SetupFirmwareMemory extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram.getDefaultPointerSize() != 8) return;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.getName().equals("Headers") && !block.getName().equals(".reloc")) {
                block.setWrite(true);
                println("Firmware mutable section: " + block.getName());
            }
        }
    }
}
