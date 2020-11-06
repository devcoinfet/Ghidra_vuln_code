from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json
import base64

#this is used to do basic bad c call  function flagging
#@wabafet 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#https://vdalabs.com/2019/03/09/automating-ghidra-writing-a-script-to-find-banned-functions/ - > far better breadth of functions than my original
badcalls = ["strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", "StrCpy",
       "StrCpyA", "StrCpyW", "lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy",
       "_ftcscpy", "strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat",
       "StrCat", "StrCatA", "StrCatW", "lstrcat", "lstrcatA", "lstrcatW", "StrCatBuff",
       "StrCatBuffA", "StrCatBuffW", "StrCatChainW", "_tccat", "_mbccat", "_ftcscat",
       "sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf", "swprintf",
       "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf",
       "vswprintf", "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN",
       "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn",
       "lstrcpynA", "lstrcpynW", "strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat",
       "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat",
       "lstrcatnA", "lstrcatnW", "lstrcatn", "gets", "_getts", "_gettws", "IsBadWritePtr",
       "IsBadHugeWritePtr", "IsBadReadPtr", "IsBadHugeReadPtr", "IsBadCodePtr", "IsBadStringPtr"]

vuln_calls_discovered = []

def get_decompilation(calle_addr,func_name):
    program = getCurrentProgram()
    ifc = DecompInterface()
    ifc.openProgram(program)

    # here we assume there is only one function named `main`
    function = getGlobalFunctions(func_name)[0]

    # decompile the function and print the pseudo C
    results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
    print(results.getDecompiledFunction().getC())
    return results.getDecompiledFunction().getC()


  
def get_address_by_name(name):
    founds = []
    funcs = getGlobalFunctions(name)
    #print("Found {} function(s) with the name '{}'".format(len(funcs), name))
    for func in funcs:
	#print("{} is located at 0x{}".format(func.getName(), func.getEntryPoint()))
        founds.append(func.getEntryPoint())

    return founds[0]



instructions = currentProgram.getListing().getInstructions(1)

for instruction in instructions:
    mnemonic = instruction.getMnemonicString()
    if mnemonic == "CALL":
        funcAddress = instruction.getOpObjects(0)[0]
        func = getFunctionContaining(toAddr(funcAddress.getOffset()))
        callingFunc = getFunctionContaining(instruction.getAddress())
        if func is not None:
           funcy_name = func.name
           for vuln_calls in badcalls:
               if funcy_name == vuln_calls:
                  print("Flagged A Vulnerable Function  "+str(funcy_name)+"\n")
                  vuln_call_info = {}
                  disass = str(get_decompilation(get_address_by_name(callingFunc.name),callingFunc.name))
                  encoded_disass = base64.b64encode(disass.encode("utf-8"))
                  vuln_call_info['Flagged_Function_Name'] = str(funcy_name)
                  vuln_call_info['Calling_Function'] = str(callingFunc)
                  vuln_call_info['Calling_FuncAddress'] = str(get_address_by_name(callingFunc.name))
                  vuln_call_info['Calling_FuncDisass'] = encoded_disass
                  vuln_calls_discovered.append(json.dumps(vuln_call_info))
                 
print("*"*50)
print(vuln_calls_discovered)
