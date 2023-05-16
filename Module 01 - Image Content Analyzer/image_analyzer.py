import os

from PIL import Image
import pytesseract
import numpy as np
import magic

"""
for file in os.listdir(os.getcwd()):
    print(file)
"""

srcdir = "C:\\Users\\fjall\\Downloads"

"""
for r, d, f in os.walk(srcdir):
    for files in f:
        if files.endswith('.jpg'):
            srcfile = os.path.join(r, files)
            print(srcfile)
"""


def get_images(srcdir):
    image_files = []
    for r, d, f in os.walk(srcdir):
        for files in f:
            srcfile = os.path.join(r, files)
            try:
                file_type = magic.from_file(srcfile)
                if 'image' in file_type.lower():
                    #print(file_type)
                    image_files.append(srcfile)
            except:
                print(f'[*] ERROR: {srcfile}')
    return image_files

def perform_ocr(image):
    img1 = np.array(Image.open(image))
    text = pyTesseract.image_to_string(img1)
    print(text)

def __main__():
    image_list = get_images(srcdir)
    for image in image_list:
        try:
            print(image)
            perform_ocr(image)
        except:
            print(f'[*] Error on file: {image}')
__main__()