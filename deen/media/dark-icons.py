#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pathlib
from lxml import etree as ET

base = pathlib.Path('.')
target = base / 'dark'

if not target.exists():
    target.mkdir()

for svg in base.glob('*.svg'):
    with svg.open() as fp:
        xml = ET.parse(fp)
        style = xml.xpath('.//svg:style', namespaces={'svg': 'http://www.w3.org/2000/svg'})
        if len(style) != 1:
            print("Invalid format for svg", str(svg))
            continue
        style = style[0]
        style.text = style.text.replace('#4d4d4d', '#adadad')
    target_svg = target / str(svg)
    with target_svg.open('wb') as fp:
        xml.write(fp, pretty_print=True)

