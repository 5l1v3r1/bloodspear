import StringIO
import Image
import ImageFilter
import ImageChops

import HTMLParser
import httplib
import time


class JsHTMLParser(HTMLParser.HTMLParser):
    def __init__(self, data=""):
        self.reset()
        self.isScriptTag = False
        self.scriptData = ""
        self.imgSrc = ""
        self.formAction = ""
        self.formMethod = ""
        self.formInputs = {}
        try:
            self.feed(data)
        except:
            pass  # binary data
    def handle_starttag(self, tag, attrs):
        if tag=="script":
            self.isScriptTag = True
        if tag=="img":
            for i in attrs:
                if i[0]=="src":
                    self.imgSrc = i[1]
        if tag=="form":
            for i in attrs:
                if i[0]=="action":
                    self.formAction = i[1]
                if i[0]=="method":
                    self.formMethod = i[1]
        if tag=="input":
            name = ""
            value = ""
            for i in attrs:
                if i[0]=="name":
                    name = i[1]
                if i[0]=="value":
                    value = i[1]
            self.formInputs[name] = value
    def handle_endtag(self, tag):
        if tag=="script":
            self.isScriptTag = False
    def handle_data(self, data):
        if self.isScriptTag:
            self.scriptData = self.scriptData+data+"\n"
    def getScriptData(self):
        return self.scriptData
    def getImgSrc(self):
        return self.imgSrc
    def getFormAction(self):
        return self.formAction
    def getFormMethod(self):
        return self.formMethod
    def getFormInputs(self):
        return self.formInputs


def prepare(filename):
    img = Image.open(filename)
    img = ImageChops.invert(img)
    #img = img.convert("L").convert("RGB")
    img = img.resize((img.size[0]*2, img.size[1]*2), Image.BILINEAR)
    img = img.filter(ImageFilter.MedianFilter(3))

    return img

# http://www.wausita.com/captcha/
# http://www.ruben-bokobza.fr/bypassing-a-captcha-with-python/
# http://wieschoo.com/tutorials/captcha-ocr-tutorial-neural-network/
def separate(img):

    # count number of pixels for each column
    colPixCnts = []
    for col in range(img.size[0]):
        pixels = list(img.crop([col, 0, col+1, img.size[1]]).getdata())
        colPixCnts.append(sum(i==0 for i in pixels))
    print colPixCnts

    # average out pixel counts for trough column
    for i in range(3, len(colPixCnts)-3, 2):
        if colPixCnts[i-3]>4 and colPixCnts[i+3]>4:
            colPixCnts[i-2:i+3] = [j+10 for j in colPixCnts[i-2:i+3]]
    print colPixCnts

    # calculate all bounding boxes of all letters
    bounds = []
    left = 0
    right = 0
    for col in range(img.size[0]): # slice all letters per column
        if left==0 and colPixCnts[col]>2:  # if (begin not set) and (col has letter)
            left = col  # then letter begin
        if left!=0 and colPixCnts[col]<=2:  # if (begin is set) and (col no letter)
            right = col  # then letter end
            if right-left>8:  # if (the letter is wide enough)
                ##############################################
                top = -1
                bottom = -1
                prev = -1
                curr = -1
                for row in range(img.size[1]):  # slice single letter per row
                    pixels = list(img.crop([left, row, right, row+1]).getdata())
                    rowPixCnt = sum(i==255 for i in pixels)
                    if rowPixCnt==(right-left):  # if (row no letter)
                        curr = row
                        if (curr-prev)>(bottom-top):  # if (the letter is tall enough)
                            top = prev
                            bottom = curr
                        prev = curr
                if (img.size[1]-prev)>(bottom-top):  # if (the letter align to bottom)
                    top = prev
                    bottom = img.size[1]
                ##############################################
                bounds.append([left, top+1, right, bottom])  # top row should has letter
            left = 0
            right = 0
    print bounds
    
    return bounds

# http://robertgawron.blogspot.hk/2013/03/breakingcaptchapython.html
def recognize(img, bounds):

    # read dataset of images for each letter
    imgs = {}
    datfile = open("ads.dat", "rt")
    line = datfile.readline()
    while line!="":
        key = line[0]
        if key not in imgs:
            imgs[key] = []
        imgs[key].append(Image.open(StringIO.StringIO(line[2:-1].decode("hex"))))
        line = datfile.readline()
    datfile.close()

    # calculate difference with dataset for each boundbox
    word = ""
    for bound in bounds:
        guess = []
        total = (img.crop(bound).size)[0]*(img.crop(bound).size)[1]*1.0
        for key in imgs:
            for pattern in imgs[key]:
                diff = ImageChops.difference(img.crop(bound), pattern.resize(img.crop(bound).size, Image.NEAREST))
                pixels = list(diff.getdata())
                samePixCnt = sum(i==0 for i in pixels)
                guess.append([samePixCnt, key])
        guess.sort(reverse=True)
        word = word+guess[0][1]
        print total, guess[0:3], guess[0][0]/total, guess[1][0]/total, guess[2][0]/total
    print word

    return word.replace("_", "")
    
def _train(img, bounds):
    datfile = open("ads.dat", "rt")
    lines = datfile.readlines()
    datfile.close()

    datfile = open("ads.dat", "at")
    for bound in bounds:
        img.crop(bound).show()
        letter = raw_input("Type in the letters you see in the image above (ENTER to skip): ")
        
        bmpfile = StringIO.StringIO()
        img.crop(bound).save(bmpfile, format="BMP")
        line = letter+"|"+bmpfile.getvalue().encode("hex")+"\n"
        if (letter!="") and (line not in lines):  # if (not skipped) and (not duplicated)
            datfile.write(line)
            print line
        bmpfile.close()
    datfile.close()


while __name__=="__main__":
    headers = {
        "Accept":"*/*",
        "Accept-Language":"en-us",
        "Accept-Encoding":"gzip, deflate",
        "User-Agent":"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20 GTB7.1 ( .NET CLR 3.5.30729)",
        "Connection":"Keep-Alive",
        }
    host = raw_input("Host (Ctrl+C to quit): ")
    url = "http://"+host
    while url!="":
        components = url.split("/")
        if components[0]=="http:" and components[1]=="":
            host = components[2]
            path = "/"+"/".join(components[3:])
        else:
            path = "/"+"/".join(components[1:])
        try:
            conn = httplib.HTTPConnection(host)
            conn.request("GET", path, "", headers)
            response = conn.getresponse()
            html = response.read()
            conn.close()
        except IOError, e:
            print e
        url = JsHTMLParser(html).getImgSrc()
    # when html is binary data
    print html.encode("hex")
    img = prepare(StringIO.StringIO(html))
    bounds = separate(img)
    Image.open(StringIO.StringIO(html)).show()
    img.show()
    #img.save("ads.bmp")
    recognize(img, bounds)
    _train(img, bounds)
    print
    time.sleep(60)

