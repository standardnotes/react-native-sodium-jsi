// global func declaration for JSI functions
// declare global {
//   function randombytes_random(): number;
// }

import { NativeModules } from 'react-native';

const Sodium = NativeModules.Sodium;

if (Sodium && typeof Sodium.install === 'function') {
  Sodium.install();
}
