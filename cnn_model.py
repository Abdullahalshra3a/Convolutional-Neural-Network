from keras.models import Sequential
from keras.layers import Conv2D, MaxPooling2D
from keras.layers import Activation, Dropout, Flatten, Dense
from keras.preprocessing.image import ImageDataGenerator, array_to_img, img_to_array, load_img
import tensorflow as tf
import time
import numpy as np
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

tf.test.gpu_device_name()
#drive.mount('/content/gdrive/')
#data_dir = "/content/drive/MyDrive/Datasets/CICDDOS2019"

model = Sequential()

model.add(Conv2D(32, (3, 3), input_shape=(30, 77, 3)))
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
model.summary()
model.compile(loss='binary_crossentropy',
              optimizer='adam',#'rmsprop',
              metrics=['accuracy'])
batch_size = 1

train_datagen = ImageDataGenerator(rescale=1. / 255,
                                   shear_range=0.2,
                                   zoom_range=0.2,
                                   horizontal_flip=True)

test_datagen = ImageDataGenerator(rescale=1. / 255)

train_generator = train_datagen.flow_from_directory(
    '/home/abdullah/Desktop/IM/Training',
    target_size=(30, 77),
    batch_size=batch_size,
    class_mode='binary')

validation_generator = test_datagen.flow_from_directory(
    '/home/abdullah/Desktop/IM/Test',
    target_size=(30, 77),
    batch_size=batch_size,
    class_mode='binary')

#initializing time instance to calculate the trianing time
start_time = time.time()

history = model.fit(
        train_generator,
        steps_per_epoch=np.math.ceil(train_generator.samples / train_generator.batch_size),
        epochs=5,
        validation_data=validation_generator,
        validation_steps=np.math.ceil(validation_generator.samples / validation_generator.batch_size),
      verbose=1)


print("--- %s seconds ---" % (time.time() - start_time))

predictions = model.predict(validation_generator)


print(predictions)
#this step is necessary if you used to predict the labels of a 3 dimensional data
predicted = np.argmax(predictions, axis =1)
# predicted = predictions
print("predicted labels are ",predicted)
print(predicted.dtype)
print(predicted.shape)


true_lbls = np.argmax(predictions, axis=1)
print(true_lbls.dtype)
print(true_lbls.shape)



print("true labels are",true_lbls)
#lets plot the train and val curve
#get the details form the history object
#print(history.history)
acc = history.history['accuracy']
val_acc = history.history['val_accuracy']
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


#calculating metrics 

from sklearn.metrics import confusion_matrix,accuracy_score,recall_score,precision_score,f1_score,roc_curve, roc_auc_score
accuracy = accuracy_score(true_lbls,predicted)
print('accuracy_score is',accuracy)
precision = precision_score(true_lbls,predicted)
print("precision is ", precision )
recall = recall_score(true_lbls,predicted)
print("recall is", recall )
f1Score = f1_score(true_lbls,predicted)
print("f1_score is",f1Score)
false_positive_rate1, true_positive_rate1, threshold1 = roc_curve(true_lbls,predicted)
print('roc_auc_score for CNN: ', roc_auc_score(true_lbls,predicted))

plt.subplots(1, figsize=(10,10))
plt.title('Receiver Operating Characteristic - CNN')
plt.plot(false_positive_rate1, true_positive_rate1)
plt.plot([0, 1], ls="--")
plt.plot([0, 0], [1, 0] , c=".7"), plt.plot([1, 1] , c=".7")
plt.ylabel('True Positive Rate')
plt.xlabel('False Positive Rate')
plt.show()


test_scores = model.evaluate(validation_generator, verbose=2)
print(test_scores)
print("Test loss:", test_scores[0])
print("Test accuracy:", test_scores[1])


