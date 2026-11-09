// Explicit seeds below come from reviewed callback registration assembly.
// @category Firmware.X99
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
public class SeedFirmwareCallbacks extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        for (String arg : args) {
            String[] pair = arg.split(":", 2);
            Address address = currentProgram.getImageBase().add(Long.parseUnsignedLong(pair[0], 16));
            if (getInstructionAt(address) == null) {
                clearListing(address, address.add(1));
                disassemble(address);
            }
            Function function = getFunctionAt(address);
            if (function == null) function = createFunction(address, pair[1]);
            if (function == null) throw new IllegalStateException("Cannot create reviewed callback " + arg);
            function.setName(pair[1], SourceType.USER_DEFINED);
            setPlateComment(address, "Reviewed code entry: source references establish this address. Name describes observed role; it is not an original vendor symbol.");
            println("SEEDED_FIRMWARE_CALLBACK " + arg);
        }
        analyzeChanges(currentProgram);
    }
}
