import os
import argparse
from argparse import RawTextHelpFormatter
from pathlib import Path
from PIL import Image
import pytesseract          # https://pypi.org/project/pytesseract/
import numpy as np
import magic                # https://pypi.org/project/python-magic/


def parse_keywords(keyword_file):
    """ Convert input file into list object """
    with open(keyword_file, 'r') as f:
        keywords = [str(x).lower().rstrip() for x in f.readlines()]     # convert to lower case and remove trailing newline characters
    return keywords


def get_images(srcdir):
    """ Recurses through directory path to identify images files using magic-byte enumeration """
    image_files = []
    excluded_extensions = ['js', 'svg', 'mp4','mov']    # js, mp4, mov matches images; svg errors on OCR, requires extension rename to .png to run properly (future feature)
    for r, d, f in os.walk(srcdir):
        for each in f:
            srcfile = os.path.join(r, each)
            try:
                if srcfile.split('.')[1] not in excluded_extensions:    # split() method used instead of endswith due to errors encountered in testing
                    file_type = magic.from_file(srcfile)
                    if 'image' in file_type.lower():
                        #print(srcfile)
                        image_files.append(srcfile)
            except:
                pass
    return image_files


def perform_ocr(image):
    """ Performs OCR using tesseract utility on input image and outputs resultant text """
    if os.name == 'nt':
        tesseract_path = r'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
    img_array = np.array(Image.open(image))          # Open image with Pillow and convert to np array for processing   
    text = pytesseract.image_to_string(img_array)    # tesseract execution, output to text; to tune, ref: https://pypi.org/project/pytesseract/
    return text


def __main__():
    parser = argparse.ArgumentParser(
        description ='image_analyzer.py is a script which will query images within a given directory path for the presence of specified keywords.',
        formatter_class = RawTextHelpFormatter,
        epilog = 'Thanks for trying image_analyzer!\n ',
    )

    parser.add_argument('-d','--directory', help='The directory path to scan.\nDefault value: [current directory]', type=str, default=os.getcwd())
    parser.add_argument('-f','--file', help='The path to the keyword list file.\nThe keyword list file should contain one term per line.\nDefault value: [./keywords.txt]', type=str, default='keywords.txt')
    #parser.add_argument('-p','--path', help='The path to the Tesseract binary.\nDefault Windows value: [C:\\Program Files\\Tesseract-OCR\\tesseract.exe]', type=str)
    parser.add_argument('-t','--text', help='Print text associated with OCR keyword matches.\nDefault value: False (--no-text)', action=argparse.BooleanOptionalAction)
    parser.set_defaults(text=False)
    args = parser.parse_args()

    keywords = parse_keywords(args.file)

    srcdir = Path(args.directory)                       # Convert arg input to path
    image_list = get_images(srcdir)                     

    for image in image_list:
        try:
            image_text = perform_ocr(image)
            if len(image_text) > 0:                     # verify OCR data exists for efficiency
                for keyword in keywords:
                    if keyword in image_text.lower():   # normalize on lower case
                        print(f'[+] Match found:\n keyword: {keyword}\n file: {image}\n')
                        if args.text:
                            print(f'********** START TEXT **********\n\n{image_text.strip()}\n\n********** END TEXT **********\n\n')
            
        except:
            print(f'[*] OCR Error on file: {image}')
            pass


__main__()