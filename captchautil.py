import tempfile
import sys
import os
import random
import shutil
from datetime import datetime,timedelta

from captcha.audio import AudioCaptcha
from captcha.image import ImageCaptcha


captchabasedir = os.environ.get("CAPTCHA_BASEDIR")
if captchabasedir:
    #base dir is configured
    if not os.path.exists(captchabasedir):
        os.makedirs(captchabasedir)
else:
    #base dir is not configured, use the tmp folder
    captchabasedir = os.path.join(tempfile.gettempdir(),"auth2captchas")
    if not os.path.exists(captchabasedir):
        os.mkdir(captchabasedir)

fontsdir = os.environ.get("CAPTCHA_FONTSDIR")
voicedir = os.environ.get("CAPTCHA_VOICEDIR") or None
if fontsdir and os.path.exists(fontsdir):
    fonts = []
    for f in os.listdir(fontsdir):
        fonts.append(os.path.join(fontsdir,f))
else:
    fonts = None

def create_captcha(kind,code,outfile):
    now = datetime.now()
    captchadir = os.path.join(captchabasedir,datetime.now().strftime("%Y-%m-%d-%H"))
    if not os.path.exists(captchadir):
        #current captchadir does not exist
        #clean the expired captchadir first
        previousdir = (now - timedelta(hours=1)).strftime("%Y-%m-%d-%H")
        for d in os.listdir(captchabasedir):
            if d == previousdir:
                #this dir is not expired
                continue
            try:
                shutil.rmtree(os.path.join(captchabasedir,d))
            except:
                #remove failed,ignore 
                pass
        #create the current captchadir.
        os.mkdir(captchadir)

    #get name of the tempfile
    if outfile:
        outfile = os.path.join(captchadir,outfile)
    else:
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
    """
    if sys.argv[1] == "testfonts":
        if not os.path.exists(fontsdir):
            os.makedirs(fontsdir)
        for f in os.listdir(fontsdir):
            os.remove(os.path.join(fontsdir,f))
        for f in os.listdir(sys.argv[2]):
            shutil.copyfile(os.path.join(sys.argv[2],f), os.path.join(fontsdir,f))
            print(create_captcha("image","0123456789","{}.png".format(f)))
            os.remove(os.path.join(fontsdir,f))
        exit(0)
    """
    kind = sys.argv[1]
    code = sys.argv[2]
    if len(sys.argv) > 3:
        outfile = sys.argv[3]
    else:
        outfile = None

    print(create_captcha(kind,code,outfile))
