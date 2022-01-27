import * as React from 'react';

import { StyleSheet, View, Text, NativeModules } from 'react-native';
import base64 from 'base64-js';

const TestResult: React.FC<{ value: boolean | undefined; name: string }> = (
  props
) => {
  const text = props.value === undefined ? '?' : props.value ? 'Pass' : 'Fail';
  const style = {
    color: props.value === undefined ? 'black' : props.value ? 'green' : 'red',
  };
  return (
    <View style={styles.testContainer}>
      <Text style={styles.testLabel}>{props.name}:</Text>
      <Text style={[styles.testResult, style]}>{text}</Text>
    </View>
  );
};

export default function App() {
  const [randombytes_buf, setRandomBytesBuf] = React.useState<boolean>();
  const [randombytes_random, setRandomBytesRandom] = React.useState<boolean>();

  // const testRandom2 = () => {
  //   setRandomBytesBuf(undefined);
  //   let freq: Array<number> = [];
  //   for (let i = 0; i < 256; ++i) freq[i] = 0;
  //   const value = global.randombytes_buf(20 * 256);
  //   let a = base64.toByteArray(value);
  //   for (let i = 0; i < a.length; ++i) ++freq[a[i]];
  //   let fail = false;
  //   for (let i = 0; i < 256 && !fail; ++i)
  //     if (!freq[i]) {
  //       console.log(a, i);
  //       fail = true;
  //     }
  //   setRandomBytesBuf(!fail);
  // };

  React.useEffect(() => {
    const message = 'hello world';
    const key = '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f';
    const nonce = '404142434445464748494a4b4c4d4e4f5051525354555657';
    const aad = key;

    const encrypted = global.crypto_aead_xchacha20poly1305_ietf_encrypt(
      message,
      nonce,
      key,
      aad
    );

    console.log('encrypted', encrypted);

    const decrypted = global.crypto_aead_xchacha20poly1305_ietf_decrypt(
      encrypted,
      nonce,
      key,
      aad
    );
    console.log('decrypted', decrypted);
    // console.log(NativeModules.Sodium);
    // setResult(global && global.randombytes_random());
    // testRandom2();
    // testRandom3();
  }, []);

  return (
    <View style={styles.container}>
      <TestResult name="randombytes_random" value={randombytes_random} />
      <TestResult name="randombytes_buf" value={randombytes_buf} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F5FCFF',
    padding: 5,
  },

  testContainer: {
    flex: 1,
    flexDirection: 'row',
    padding: 5,
  },

  testLabel: {
    flex: 4,
    textAlign: 'left',
    color: '#333333',
  },

  testResult: {
    flex: 1,
    textAlign: 'center',
  },
  instructions: {
    textAlign: 'left',
    color: '#333333',
    marginBottom: 5,
  },
});
