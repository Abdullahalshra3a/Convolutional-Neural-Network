from keras.models import Sequential
from keras.layers import Conv2D,Activation,MaxPooling2D,Dense,Flatten,Dropout
import numpy as np
from keras.preprocessing.image import ImageDataGenerator
from IPython.display import display
import matplotlib.pyplot as plt
from PIL import Image
from sklearn.metrics import classification_report, confusion_matrix
import numpy
import tensorflow as tf

classifier = Sequential()
classifier.add(Conv2D(32,(3,3),input_shape=(30,77,3)))
classifier.add(Activation('relu'))
classifier.add(MaxPooling2D(pool_size =(2,2)))
classifier.add(Conv2D(32,(3,3)))
classifier.add(Activation('relu'))
classifier.add(MaxPooling2D(pool_size =(2,2)))
classifier.add(Conv2D(64,(3,3)))
classifier.add(Activation('relu'))
classifier.add(MaxPooling2D(pool_size =(2,2)))
classifier.add(Flatten())
classifier.add(Dense(64))
classifier.add(Activation('relu'))
classifier.add(Dropout(0.5))
classifier.add(Dense(1))
classifier.add(Activation('sigmoid'))
classifier.summary()
opt = tf.keras.optimizers.Adam(lr=0.001, decay=1e-6)
classifier.compile(loss='mse',
    optimizer=opt,
    metrics=['accuracy'],)
train_datagen = ImageDataGenerator(rescale =1./255,
                                   shear_range =0.2,
                                   zoom_range = 0.2,
                                   horizontal_flip =True)

test_datagen = ImageDataGenerator(rescale = 1./255)

batchsize=32
training_set = train_datagen.flow_from_directory('/home/abdullah/Desktop/IM/Training/',
                                                target_size=(60,60),
                                                batch_size= batchsize,
                                                class_mode='binary')

test_set = test_datagen.flow_from_directory('/home/abdullah/Desktop/IM/Test/',
                                           target_size = (60,60),
                                           batch_size = batchsize,
                       shuffle=False,
                                           class_mode ='binary')

#initializing time instance to calculate the trianing time
start_time = time.time()
history=classifier.fit(training_set,
                        steps_per_epoch =len(training_set) // batchsize,
                        epochs = 5,
                        validation_data =test_set,
                        validation_steps = len(test_set) // batchsize)

#lets plot the train and val curve
#get the details form the history object
print(history.history)
acc = history.history['accuracy']
val_acc = history.history['val_acc']
loss = history.history['loss']
val_loss = history.history['val_loss']

epochs = range(1, len(acc) + 1)

#Train and validation accuracy
plt.plot(epochs, acc, 'b', label='Training accurarcy')
plt.plot(epochs, val_acc, 'r', label='Validation accurarcy')
plt.title('Training and Validation accurarcy')
plt.legend()



plt.figure()
#Train and validation loss
plt.plot(epochs, loss, 'b', label='Training loss')
plt.plot(epochs, val_loss, 'r', label='Validation loss')
plt.title('Training and Validation loss')
plt.legend()

plt.show()

