#!/bin/bash
echo "Mounting $1..."
hdiutil attach -imagekey diskimage-class=CRawDiskImage $1
