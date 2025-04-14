// BinScrybe Importer for Ghidra
// Automatically imports BinScrybe findings into the current Ghidra project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * This script imports BinScrybe analysis results into Ghidra.
 * It creates bookmarks and comments at the specified addresses
 * from the analysis.
 */
public class BinScrybeImporter extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("BinScrybe Importer - Starting import...");
        
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        int importCount = 0;
        
        // Sample data - in a real script, this would be provided by the Python code
        String[][] findings = {
            {"0x140001000", "host-interaction/file-system/read"},
            {"0x140001050", "anti-analysis/anti-debugging/check-debugger"},
            {"0x140001100", "crypto/encrypt"}
        };
        
        // Import BinScrybe findings as bookmarks and comments
        for (String[] finding : findings) {
            String addr = finding[0];
            String capability = finding[1];
            
            try {
                Address address = toAddr(addr);
                
                // Create a bookmark
                bookmarkManager.setBookmark(address, BookmarkType.INFO, "BinScrybe", capability);
                
                // Add a comment
                setPreComment(address, "BinScrybe: " + capability);
                
                // If this is a function start, rename the function to something more descriptive
                Function func = getFunctionAt(address);
                if (func != null) {
                    String newName = "binscrybe_" + capability.replace("/", "_").replace("-", "_");
                    try {
                        func.setName(newName, SourceType.USER_DEFINED);
                    } catch (DuplicateNameException e) {
                        // Function name already exists, append a number
                        func.setName(newName + "_" + importCount, SourceType.USER_DEFINED);
                    }
                }
                
                importCount++;
                
            } catch (Exception e) {
                println("Failed to import " + addr + ": " + e.getMessage());
            }
        }
        
        println("BinScrybe Importer - Completed: " + importCount + " findings imported.");
    }
} 