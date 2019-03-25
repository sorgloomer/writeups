import os
import sys
__path = os.path.dirname(os.path.abspath(__file__))
os.chdir(__path)
sys.path.insert(0, __path)

import numpy as np
from matplotlib import pyplot as plt
from app import mse, class_names
from networks.lenet import LeNet
import keras.backend as K
from keras.preprocessing import image


def predictimg(image,lenet):
    confidence = lenet.predict(image)[0]
    predicted_class = np.argmax(confidence)
    return  predicted_class, class_names[predicted_class],confidence[predicted_class]


def layer_without_activation(dense):
    output = K.dot(dense.input, dense.kernel)
    if dense.use_bias:
        output = K.bias_add(output, dense.bias, data_format='channels_last')
    return output

def main():
    # Use gradient-descend to minimize the confidence of the "good" prediction
    lenet = LeNet()
    print(lenet._model.layers)
    # SoftMax activation on the last layer shrinks our gradients so much it is impossible to
    # do floating point computation, so we just peel it off from the output
    sym_outouts = layer_without_activation(lenet._model.layers[-1])
    print("sym_outouts", sym_outouts)
    sym_inputs = lenet._model.inputs[0]
    print("sym_inputs", sym_inputs)

    for image_index in range(8):
        # K.set_floatx('float64')

        imageori = plt.imread("static/{}.jpg".format(image_index)).copy().astype("float")

        output_path = "broken/{}.jpg".format(image_index)

        original_prediction = predictimg(imageori, lenet)
        original_prediction_index = original_prediction[0]

        loss = -sym_outouts[0][original_prediction_index]
        # print("LOSS", loss)
        fn = K.function([sym_inputs], K.gradients(loss, sym_inputs))

        imagenew = imageori.copy()
        for i in range(100):
            bump = fn([[imagenew]])[0][0]
            imagenew = np.clip(imagenew.copy() + bump, 0, 255)

            # saving to jpg alters the image so check whether our prediction is broken after a reload
            plt.imsave(output_path, imagenew.astype("uint8"), format="jpg")
            broken = plt.imread(output_path)

            new_prediction = predictimg(broken, lenet)
            # print("ITER", mse(imagenew, imageori))
            if new_prediction[0] != original_prediction_index:
                break
        else:
            raise Exception("COULDNT BREAK {}".format(image_index))


        broken = plt.imread(output_path)
        print("ORIGINAL PREDICTION", predictimg(imageori, lenet))
        print("BROKEN PREDICTION", predictimg(broken, lenet))
        print("mse(broken, imageori)", mse(broken, imageori))
        print("mse(imagenew, imageori)", mse(imagenew, imageori))

        print("FINISHED {}".format(image_index))
        print()


if __name__ == "__main__":
    main()
