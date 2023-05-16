# Module 01 - Image Content Analyzer

## Why?

Image files do not contain queryable text; requires manual analysis to review

Discovery Use Cases
- [Offensive] Post-exploitation for sensitive content
- [Defensive] Data Loss Prevention
- [Defensive] Data Classification and Marking requirements

## How?

1. Identify file type based on extension and/or magic byte
2. Perform OCR on file to produce companion text
3. Query companion text for matches against a provided wordlist. Wordlist can contain keywords of interest based on use case (e.g. authentication token identifiers, regulated data markers, ...) 

## Future Improvements

Make more better

## Install

Install Python Magic for file magic-byte identification
```
pip3 install python-magic
pip3 install python-magic-bin
```

Install Tesseract (Windows)
- download latest installer from https://digi.bib.uni-mannheim.de/tesseract/

```
pip3  install pytesseract
```

## Demonstration

link to video here
