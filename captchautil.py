import tempfile
import sys
import os
import random
import shutil
from datetime import datetime,timedelta

from captcha.audio import AudioCaptcha
from captcha.image import ImageCaptcha


homedir = os.path.join(tempfile.gettempdir(),"auth2captchas")
if not os.path.exists(homedir):
    os.mkdir(homedir)

fontsdir = os.environ.get("CAPTCHA_FONTSDIR")
voicedir = os.environ.get("CAPTCHA_VOICEDIR")

if fontsdir and os.path.exists(fontsdir):
    fonts = []
    for f in os.listdir(fontsdir):
        fonts.append(os.path.join(fontsdir,f))
else:
    fonts = None

def create_captcha(kind,code):
    now = datetime.now()
    captchadir = os.path.join(homedir,datetime.now().strftime("%Y-%m-%d-%H"))
    if not os.path.exists(captchadir):
        #current captchadir does not exist
        #clean the expired captchadir first
        previousdir = (now - timedelta(hours=1)).strftime("%Y-%m-%d-%H")
        for d in os.listdir(homedir):
            if d == previousdir:
                #this dir is not expired
                continue
            try:
                shutil.rmtree(os.path.join(homedir,d))
            except:
                #remove failed,ignore 
                pass
        #create the current captchadir.
        os.mkdir(captchadir)

    #get name of the tempfile
    with tempfile.NamedTemporaryFile(mode='w+b', buffering=-1, suffix=".png" if kind == "image" else ".wav", prefix="auth2_captcha_", dir=captchadir, delete=False, delete_on_close=False) as f:
        outfile = f.name
    if kind == "image":
        width = 30 * len(code)
        if fonts:
            if len(fonts) <= 3:
                image = ImageCaptcha(fonts=fonts,width=width)
            else:
                selectedfonts = [None] * 3
                index = 0
                while index < 3:
                    f = fonts[random.choice(range(len(fonts)))]
                    if f in selectedfonts:
                        continue
                    selectedfonts[index] = f
                    index += 1
                image = ImageCaptcha(fonts=selectedfonts,width=width)
        else:
            image = ImageCaptcha(width=width)

        image.write(code,outfile)
    else:
        audio = AudioCaptcha(voicedir=voicedir)
        audio.write(code, outfile)

    return outfile


    
    

if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise Exception("Please specified the kind and code as first and second arguments.")
    kind = sys.argv[1]
    code = sys.argv[2]

    print(create_captcha(kind,code))
