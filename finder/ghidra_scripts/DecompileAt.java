// Ghidra headless script: decompile the function containing a given address.
//
// Written in Java rather than Python because Ghidra compiles and runs .java
// scripts natively with no extra interpreter setup, which is one less thing to
// break on demo day.
//
// Usage (via analyzeHeadless):
//   -postScript DecompileAt.java 0x401192 /path/to/output.json
//
// @category Sanjeevani

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DecompileAt extends GhidraScript {

    private static String jsonEscape(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private String decompileOne(DecompInterface decomp, Function fn) {
        DecompileResults res = decomp.decompileFunction(fn, 60, monitor);
        if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
            return res.getDecompiledFunction().getC();
        }
        return "";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("SANJEEVANI_ERROR need <address> <output.json>");
            return;
        }

        String addrText = args[0].startsWith("0x") ? args[0].substring(2) : args[0];
        Address addr = toAddr(Long.parseLong(addrText, 16));
        String outPath = args[1];

        Function fn = getFunctionContaining(addr);
        if (fn == null) {
            // The binary is stripped, so Ghidra may not have carved a function
            // out of this address. Say so plainly instead of writing junk.
            Files.write(Paths.get(outPath),
                ("{\"found\": false, \"address\": \"" + addr + "\"}").getBytes(StandardCharsets.UTF_8));
            println("SANJEEVANI_ERROR no function contains " + addr);
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String c = decompileOne(decomp, fn);

        // Also decompile what this function calls, one level down.
        //
        // The crash address does not always land in the function that holds the
        // bug. A stack overflow in greet() only faults once greet RETURNS, so
        // the blame frequently lands on main - whose body is just a call to
        // greet and contains no bug at all. Handing that to the patch step
        // would be asking it to fix code that is already correct.
        StringBuilder callees = new StringBuilder("[");
        boolean first = true;
        for (Function callee : fn.getCalledFunctions(monitor)) {
            if (callee.isExternal() || callee.isThunk()) continue;   // skip libc
            if (first) first = false; else callees.append(",");
            callees.append("{")
                   .append("\"function\": \"").append(jsonEscape(callee.getName())).append("\",")
                   .append("\"entry\": \"").append(callee.getEntryPoint()).append("\",")
                   .append("\"decompiled\": \"")
                   .append(jsonEscape(decompileOne(decomp, callee))).append("\"")
                   .append("}");
        }
        callees.append("]");
        decomp.dispose();

        String json = "{"
            + "\"found\": true,"
            + "\"address\": \"" + addr + "\","
            + "\"function\": \"" + jsonEscape(fn.getName()) + "\","
            + "\"entry\": \"" + fn.getEntryPoint() + "\","
            + "\"size\": " + fn.getBody().getNumAddresses() + ","
            + "\"decompiled\": \"" + jsonEscape(c) + "\","
            + "\"callees\": " + callees
            + "}";
        Files.write(Paths.get(outPath), json.getBytes(StandardCharsets.UTF_8));
        println("SANJEEVANI_OK " + fn.getName() + " @ " + fn.getEntryPoint());
    }
}
