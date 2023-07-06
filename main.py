import frida, sys,time
def on_message(message, data):
    print("     [-] ", message)    
    try:
        with open("temp.log", "a") as f:
            f.write(message['payload'] + "\n")
    except:
        print(f"[!] Error: {message}") 

def on_detached(reason, crash):
    if reason == "process-terminated":
        print("[*] Process terminated")
    else:
        print("process detached code：", reason)

def Crate():
    #process_id = frida.spawn([r"C:\Tools\wke\binaries\WKE64.exe"])
    session = frida.attach(process_id)
    with open(".\\demo.js", "r") as f:
        contents = f.read()
    script = session.create_script(contents)
    script.on('message', on_message)
    script.load()
    frida.resume(process_id)
    sys.stdin.read()
    session.detach()

def StartKeepHook(processName):
    print("[*] Start monitor: ",processName)
    while(True):
        while(True):
            try :
                session = frida.attach(processName)
                break
            except:
                time.sleep(0.1)
        print("[*] Find it. inject: ",processName)
        with open(".\\demo.js", "r") as f:
            contents = f.read()
        script = session.create_script(contents)
        script.on('message', on_message)
        session.on('detached', on_detached)
        script.load()
        while session.is_detached == False :
            time.sleep(1)
        session.detach()

def main(): 
    titile = '''
 d8b                       d8b                                   d8b 
 ?88                       ?88                                   88P 
  88b                       88b                                 d88  
  888888b  d8888b  d8888b   888  d88'     d888b8b   d8888b  d888888  
  88P `?8bd8P' ?88d8P' ?88  888bd8P'     d8P' ?88  d8P' ?88d8P' ?88  
 d88   88P88b  d8888b  d88 d88888b       88b  ,88b 88b  d8888b  ,88b 
d88'   88b`?8888P'`?8888P'd88' `?88b,    `?88P'`88b`?8888P'`?88P'`88b
                                                )88                  
                                               ,88P                  
                                           `?8888P                   
'''
    print(titile)
    processName = "TestVeh.exe" 
    StartKeepHook(processName)

main()
