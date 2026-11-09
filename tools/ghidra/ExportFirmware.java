// Export analysis artifacts; this script does not modify firmware image files.
// @category Firmware.X99
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class ExportFirmware extends GhidraScript {
    private String bytesHex(byte[] bytes) {
        StringBuilder b = new StringBuilder();
        for (byte value : bytes) b.append(String.format("%02x", value & 255));
        return b.toString();
    }
    private String rva(Address address) {
        return "0x" + Long.toUnsignedString(address.subtract(currentProgram.getImageBase()), 16);
    }
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("ExportFirmware.java OUTPUT_DIR");
        Path output = Paths.get(args[0]);
        Files.createDirectories(output);
        String name = currentProgram.getName().replaceFirst("\\.pe$", "");
        JsonObject root = new JsonObject();
        root.addProperty("program", name);
        root.addProperty("language", currentProgram.getLanguageID().toString());
        root.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        root.addProperty("image_base", "0x" + currentProgram.getImageBase().toString());
        root.addProperty("executable_sha256", currentProgram.getExecutableSHA256());
        root.addProperty("interpretation", "Decompiled C is approximate; auto-detected functions and inferred types require review.");
        JsonArray functions = new JsonArray();
        JsonArray blocks = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject item = new JsonObject();
            item.addProperty("name", block.getName());
            item.addProperty("start", block.getStart().toString());
            item.addProperty("size", block.getSize());
            item.addProperty("execute", block.isExecute());
            blocks.add(item);
        }
        root.add("blocks", blocks);
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);
        int complete = 0, failed = 0;
        try (PrintWriter c = new PrintWriter(Files.newBufferedWriter(output.resolve(name + ".c"), StandardCharsets.UTF_8));
             PrintWriter assembly = new PrintWriter(Files.newBufferedWriter(output.resolve(name + ".asm"), StandardCharsets.UTF_8))) {
            c.println("/* Approximate Ghidra decompilation of " + name + "; not original or rebuildable source. */");
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Function f = iterator.next();
                if (f.isExternal()) continue;
                JsonObject item = new JsonObject();
                item.addProperty("name", f.getName());
                item.addProperty("entry", f.getEntryPoint().toString());
                item.addProperty("rva", rva(f.getEntryPoint()));
                item.addProperty("signature", f.getPrototypeString(false, false));
                item.addProperty("body_bytes", f.getBody().getNumAddresses());
                JsonArray ranges = new JsonArray();
                for (AddressRange range : f.getBody().getAddressRanges()) {
                    JsonArray pair = new JsonArray();
                    pair.add(rva(range.getMinAddress())); pair.add(rva(range.getMaxAddress()));
                    ranges.add(pair);
                }
                item.add("body_ranges_rva", ranges);
                JsonArray calls = new JsonArray();
                for (Function callee : f.getCalledFunctions(monitor)) {
                    JsonObject target = new JsonObject();
                    target.addProperty("name", callee.getName());
                    target.addProperty("entry", callee.getEntryPoint().toString());
                    target.addProperty("rva", rva(callee.getEntryPoint()));
                    calls.add(target);
                }
                item.add("calls", calls);
                DecompileResults result = decompiler.decompileFunction(f, 30, monitor);
                boolean success = result.decompileCompleted() && result.getDecompiledFunction() != null;
                item.addProperty("decompiled", success);
                c.printf("\n/* Function %s at %s; RVA %s */\n", f.getName(), f.getEntryPoint(), rva(f.getEntryPoint()));
                if (success) { c.println(result.getDecompiledFunction().getC()); complete++; }
                else { item.addProperty("decompile_error", result.getErrorMessage()); c.println("/* DECOMPILATION FAILED */"); failed++; }
                JsonArray instructions = new JsonArray();
                InstructionIterator listing = currentProgram.getListing().getInstructions(f.getBody(), true);
                assembly.printf("\n; %s @ %s RVA %s\n", f.getName(), f.getEntryPoint(), rva(f.getEntryPoint()));
                while (listing.hasNext()) {
                    Instruction instruction = listing.next();
                    JsonObject ins = new JsonObject();
                    ins.addProperty("rva", rva(instruction.getAddress()));
                    ins.addProperty("bytes", bytesHex(instruction.getBytes()));
                    ins.addProperty("mnemonic", instruction.getMnemonicString());
                    ins.addProperty("text", instruction.toString());
                    instructions.add(ins);
                    assembly.printf("%s  %-32s %s\n", instruction.getAddress(), bytesHex(instruction.getBytes()), instruction);
                }
                item.add("instructions", instructions);
                functions.add(item);
            }
            if (monitor.isCancelled()) throw new IOException("export cancelled");
            if (c.checkError() || assembly.checkError()) throw new IOException("failed to write export");
        } finally { decompiler.dispose(); }
        root.add("functions", functions);
        root.addProperty("decompiled_functions", complete);
        root.addProperty("failed_functions", failed);
        try (Writer writer = Files.newBufferedWriter(output.resolve(name + ".json"), StandardCharsets.UTF_8)) {
            new GsonBuilder().setPrettyPrinting().create().toJson(root, writer);
        }
        Files.write(output.resolve(".bme-export-complete"), new byte[] {1});
        println("FIRMWARE_EXPORT " + name + " functions=" + functions.size() + " decompiled=" + complete + " failed=" + failed);
    }
}
