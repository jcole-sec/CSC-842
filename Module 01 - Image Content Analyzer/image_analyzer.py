import os
import argparse

from PIL import Image
import pytesseract          # https://pypi.org/project/pytesseract/
import numpy as np
import magic                # python magic byte detection library


"""
for r, d, f in os.walk(srcdir):
    for files in f:
        if files.endswith('.jpg'):
            srcfile = os.path.join(r, files)
            print(srcfile)
"""


def get_images(srcdir):
    image_files = []
    excluded_extensions = ['.js', '.svg', '.mp4','.mov']
    for r, d, files in os.walk(srcdir):
        files = [os.path.join(r, f) for f in files]# if not f.lower().endswith(ext)]
        for each in files:
            #srcfile = os.path.join(r, each)
            try:
                for ext in excluded_extensions:
                    if not each.endswith(ext):
                        file_type = magic.from_file(each)
                        if 'image' in file_type.lower() and not 'SVG' in file_type:
                            #print(file_type)
                            image_files.append(each)
            except:
                print(f'[*] MAGIC Error on file: {each}')
    return image_files


def perform_ocr(image):
    tesseract_path = r'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
    pytesseract.pytesseract.tesseract_cmd = tesseract_path
    img1 = np.array(Image.open(image))
    text = pytesseract.image_to_string(img1)
    return text


def __main__():
    parser = argparse.ArgumentParser(description='image_analyzer.py is a Python script which will query images within a given directory path for the presence of specified keywords.')
    parser.add_argument('-d','--directory', help='directory path to scan', type=str, default=os.getcwd())
    #parser.add_argument()
    args = parser.parse_args()

    srcdir = 'C:\\Users\\fjall\\Downloads'
    

    keywords = ['secret', 'username', 'password', 'credential', 'spider']
    image_list = get_images(srcdir)
    for image in image_list:
        try:
            image_text = perform_ocr(image)
            if len(image_text) > 0:
                for keyword in keywords:
                    if keyword in image_text.lower():
                        print(f'[+] Match found:\n keyword: {keyword}\n file: {image}\n text: {image_text.strip()}\n')
            
        except:
            print(f'[*] OCR Error on file: {image}')
            pass


__main__()