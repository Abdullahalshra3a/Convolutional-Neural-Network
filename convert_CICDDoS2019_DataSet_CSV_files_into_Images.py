import os, sys
import pandas as pd
import numpy as np
import cv2
from tqdm import tqdm
from sklearn import preprocessing

#DataPath of your CICDDOS CSV files.
DataPath = '/home/abdullah/Desktop/CICDDDoS2019/Training_final/'
#Get List of files in this directory by names.
FilesList = os.listdir(DataPath)

count = 0
#DataPath of a folder to export images into it.
dstpath = '/home/abdullah/Desktop/IM/Training'
dstpath2 = dstpath + 'Benign_'

for FileName in FilesList:
    print(FileName + ' DataFrame')

    dstpath3 = dstpath + FileName.replace('.csv', '') + 'Images'
    os.mkdir(dstpath3)
    #Reading the CSV into the DataFrame.
    df = pd.read_csv(DataPath + FileName)
    #Dropping unused columns.
    '''
    df.drop(labels=[
        'Unnamed: 0', 'Flow ID', ' Source IP', ' Source Port',
        ' Destination IP', ' Destination Port', ' Protocol', ' Timestamp',
        'SimillarHTTP', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
        'FIN Flag Count', ' PSH Flag Count', ' ECE Flag Count',
        'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate',
        ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
        ' RST Flag Count', ' Fwd Header Length.1', 'Subflow Fwd Packets',
        ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes'
    ],axis=1, errors='ignore', inplace=True)#axis : {0 or ‘index’, 1 or ‘columns’}, default 0
    '''
    df.drop(labels=['Unnamed: 0', 'Flow ID', ' Source IP', ' Source Port', ' Destination IP', ' Destination Port','SimillarHTTP', ' Timestamp'], axis=1, errors='ignore', inplace=True)
    #Replacing the infinity values with NaN.
    #print (len(df.columns.values))
    #print (df.index.values)
    #sys.exit(0)
    df = df.replace([np.inf, -np.inf], np.nan)
    #Dropping NaN values.
    df.dropna(inplace=True)#axis : {0 or ‘index’, 1 or ‘columns’}, default 0
    
    print('Split Benign & Malicious Traffic')
    benign = df[df.loc[:, 'label'] == 'BENIGN']
    Malicious = df[df.loc[:, 'label'] != 'BENIGN']
    print (len(df.columns.values))
    if len(benign) > 0:
       #print(len(benign))
       print('Normalize the Benign Traffic')
       benign.drop(['label'], axis=1, inplace=True)
       minmax_scale = preprocessing.MinMaxScaler(feature_range=(0, 255))#RGB SYSYTEM VALUES
       benign1 = minmax_scale.fit_transform(benign)
       benign = pd.DataFrame(benign1)
       r1 = int(len(benign) / 90)

       print('Generate %d Benign Images' % (r1))
       for i in tqdm(range(0, r1)):
          p = i * 90
          q = p + 30
          img = np.zeros([30, 77, 3])
          img[:, :, 0] = benign.iloc[p:q, 0:77].values
          img[:, :, 1] = benign.iloc[q:q + 30, 0:77].values
          img[:, :, 2] = benign.iloc[q + 30:q + 60, 0:77].values

          path ='/home/abdullah/Desktop/IM/Training/Normal' 
          ImageName = FileName.replace('.csv', '_')+str(i) + '_benign.png'
          cv2.imwrite(os.path.join(path , ImageName),img)
          cv2.waitKey(0)
          #print(i)
    if len(Malicious) > 0:
       print('Normalize the Malicious Traffic')
       Malicious.drop(['label'], axis=1, inplace=True)
       minmax_scale = preprocessing.MinMaxScaler(feature_range=(0, 255))
       Malicious1 = minmax_scale.fit_transform(Malicious)
       Malicious = pd.DataFrame(Malicious1)

    #Check the size of Benign & Malicious Traffic

       r2 = int(len(Malicious) / 90)

    

       print('Generate %d Malicious Images' % (r2))
       for i in tqdm(range(0, r2)):
          p = i * 90
          q = p + 30
          img = np.zeros([30, 77, 3])
          img[:, :, 0] = Malicious.iloc[p:q, 0:77].values
          img[:, :, 1] = Malicious.iloc[q:q + 30, 0:77].values
          img[:, :, 2] = Malicious.iloc[q + 30:q + 60, 0:77].values


          path ='/home/abdullah/Desktop/IM/Training/Attack' 
          ImageName = FileName.replace('.csv', '_')+ str(i) + '_Malicious.png'
          cv2.imwrite(os.path.join(path , ImageName),img)
          cv2.waitKey(0)
          #print(i)
    print('Finished')
