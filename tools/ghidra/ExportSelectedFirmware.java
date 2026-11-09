// @category Firmware.X99
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.*;
import java.nio.file.*;
public class ExportSelectedFirmware extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Paths.get(args[0]);
        Files.createDirectories(output);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        String name = currentProgram.getName().replaceFirst("\\.pe$", "");
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(output.resolve(name+"-reviewed.c")))) {
            writer.println("/* Reviewed function names are descriptive annotations, not recovered vendor symbols. */");
            for (int i=1; i<args.length; i++) {
                Function function=getFunctionAt(currentProgram.getImageBase().add(Long.parseUnsignedLong(args[i],16)));
                if (function==null) throw new IllegalArgumentException("Missing reviewed function: "+args[i]);
                DecompileResults result=decompiler.decompileFunction(function,60,monitor);
                if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
                writer.println("\n/* Address "+function.getEntryPoint()+"; RVA 0x"+args[i]+" */");
                writer.println(result.getDecompiledFunction().getC());
            }
        } finally { decompiler.dispose(); }
    }
}
