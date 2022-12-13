from PIL import Image
import numpy as np
import os

SIZE = 500

def getResult(img):
    Image.fromarray(np.uint8(img)).save('test.png')
    os.system('nocode.exe test.png > nul')
    return np.asarray(Image.open('result.png'))

img = np.zeros((SIZE,SIZE,3), dtype = int)
black = getResult(img)
# move = np.zeros(SIZE, dtype = int)
# np.savetxt('move.txt', move)
move = np.loadtxt('move.txt', dtype = int)
# print(move)
# exit()

def shuffle(img):
    new_img = np.zeros((SIZE,SIZE,3), dtype = int)
    for i in range(SIZE):
        new_img[:,i] = img[:,move[i]]
    return new_img

def compare(img):
    new_img = np.zeros((SIZE,SIZE,3), dtype = int)
    for i in range(SIZE):
        for j in range(SIZE):
            if (img[i,j] == black[i,j]).all():
                new_img[i,j,:] = 0
            else:
                new_img[i,j,:] = 255
    return new_img

flag = np.asarray(Image.open('flag_enc.png'))
flag = shuffle(compare(flag))
Image.fromarray(np.uint8(flag)).save('flag.png')