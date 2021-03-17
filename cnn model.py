from keras.models import Sequential
from keras.layers import Conv2D, MaxPooling2D
from keras.layers import Activation, Dropout, Flatten, Dense
from keras.preprocessing.image import ImageDataGenerator, array_to_img, img_to_array, load_img
import tensorflow as tf
tf.test.gpu_device_name()
#drive.mount('/content/gdrive/')
#data_dir = "/content/drive/MyDrive/Datasets/CICDDOS2019"

model = Sequential()

model.add(Conv2D(32, (3, 3), input_shape=(60, 60, 3)))
model.add(Activation('relu'))
model.add(MaxPooling2D(pool_size=(2, 2)))

model.add(Conv2D(32, (3, 3)))
model.add(Activation('relu'))
model.add(MaxPooling2D(pool_size=(2, 2)))

model.add(Conv2D(32, (3, 3)))
model.add(Activation('relu'))
model.add(MaxPooling2D(pool_size=(2, 2)))

model.add(Flatten())
model.add(Dense(32))
model.add(Activation('relu'))
model.add(Dropout(0.5))
model.add(Dense(1))
model.add(Activation('sigmoid'))
model.compile(loss='binary_crossentropy',
              optimizer='rmsprop',
              metrics=['accuracy'])
batch_size = 32
train_datagen = ImageDataGenerator(rescale=1. / 255,
                                   shear_range=0.2,
                                   zoom_range=0.2,
                                   horizontal_flip=True)
test_datagen = ImageDataGenerator(rescale=1. / 255)
train_generator = train_datagen.flow_from_directory(
    '/home/abdullah/Desktop/IM/Training/',
    target_size=(60, 60),
    batch_size=batch_size,
    class_mode='binary')
validation_generator = test_datagen.flow_from_directory(
    '/home/abdullah/Desktop/IM/Test/',
    target_size=(60, 60),
    batch_size=batch_size,
    class_mode='binary')
