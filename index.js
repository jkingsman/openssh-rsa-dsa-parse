var atob = require("atob");

/**
 * Simple, fast parsing of OpenSSH RSA and DSA keys to programmatically access key type, length, and and multiple key formats
 *
 * @param  {String} key
 * @module OpenSSLKey
 */
var OpenSSLKey = function (key) {
  this.key = key;
  this.keyType = key.split(" ")[0];
  this.rawkey = key.split(" ")[1];
  try{
    this.keyComment = key.split(" ")[2];
  } catch(err){
    this.keyComment = null;
  }

  this.byteArray = this._stringToBytes(atob(this.rawkey));
  this.slicedArray = [];

  this.wordLength = 4;
  this._load();
}

/**
 * Load key data
 *
 * @private
 * @module OpenSSLKey
 */
OpenSSLKey.prototype._load = function () {
  var loadingArray = this.byteArray,
    length, capture;

  while (loadingArray.length > 0) {
    length = loadingArray.slice(0, this.wordLength);
    capture = loadingArray.slice(this.wordLength, this._byteArrayToLong(length) + this.wordLength);
    this.slicedArray.push(capture);

    loadingArray = loadingArray.slice(this._byteArrayToLong(length) + this.wordLength);
  }

  if (this.keyType === "ssh-rsa") {
    this.modulusLength = this.getSlicedByteArray()[2].length * 8 - 8;
  } else if (this.keyType === "ssh-dss" || this.keyType === "ssh-dsa") {
    this.modulusLength = this.getSlicedByteArray()[1].length * 8 - 8;
  } else{
    this.modulusLength = null;
  }
};

/**
 * Return the original input as a string
 *
 * @return {String}
 * @module OpenSSLKey
 */
OpenSSLKey.prototype.getKey = function () {
  return this.key;
};

/**
 * Return the key type as a string
 *
 * @return {String}
 * @module OpenSSLKey
 */
OpenSSLKey.prototype.getKeyType = function () {
  return this.keyType;
};

/**
 * Return the key data as a string
 *
 * @return {String}
 * @module OpenSSLKey
 */
OpenSSLKey.prototype.getData = function () {
  return this.rawkey;
};

/**
 * Return the key (modulus) length as a number
 *
 * @return {Number}
 * @module OpenSSLKey
 */
OpenSSLKey.prototype.getKeyLength = function () {
  return this.modulusLength;
};

/**
 * Return the key's comment, if it has one
 *
 * @return {String|Null}
 * @module OpenSSLKey
 */
OpenSSLKey.prototype.getComment = function () {
  return this.keyComment;
};

/**
 * Return the key as an array of bytes
 *
 * @return {Number|Array}
 * @module OpenSSLKey
 */
OpenSSLKey.prototype.getByteArray = function () {
  return this.byteArray;
};

/**
 * Return the sliced key as an array of arrays of bytes, broken on data boundaries
 *
 * @return {Number|Array|Array}
 * @module OpenSSLKey
 */
OpenSSLKey.prototype.getSlicedByteArray = function () {
  return this.slicedArray;
};

/**
 * Returns an array of bytes that represet a string
 *
 * @return {Number|Array}
 * @param  {String} str
 * @module OpenSSLKey
 * @private
 */
OpenSSLKey.prototype._stringToBytes = function (str) {
  var character,
      stack,
      byteArray = [],
      i;
  for (i = 0; i < str.length; i++) {
    character = str.charCodeAt(i);
    stack = [];
    do {
      stack.push(character & 0xFF);
      character >>= 8;
    }
    while (character);
    byteArray = byteArray.concat(stack.reverse());
  }
  return byteArray;
};

/**
 * Returns a string representation of a byte array
 *
 * @return {String}
 * @param  {Number|Array} array
 * @module OpenSSLKey
 * @private
 */
OpenSSLKey.prototype._bytesToString = function (array) {
  var result = "",
      i;
  for (i = 0; i < array.length; i++) {
    result += String.fromCharCode(parseInt(array[i]));
  }
  return result;
};

/**
 * Returns an array of bytes that represet a string
 *
 * @return {Number}
 * @param  {Number|Array} byteArray
 * @module OpenSSLKey
 * @private
 */
OpenSSLKey.prototype._byteArrayToLong = function (byteArray) {
  var value = 0,
      i;
  for (i = 0; i < byteArray.length; i++) {
    value = (value * 256) + byteArray[i];
  }
  return value;
};

module.exports = OpenSSLKey;
