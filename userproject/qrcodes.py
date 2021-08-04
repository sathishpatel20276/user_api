import qrcode
img=qrcode.make("https://www.youtube.com/")
img.save("hello1.jpg")