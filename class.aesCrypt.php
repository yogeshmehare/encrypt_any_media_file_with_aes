<?php

/*
 * A clone of AESCrypt encryption/decryption in php
 * allows compatibility between this native php
 * version and the existing AESCrypt applications
 * for Linux OSx and Win
 * Coded for compatibility not efficiency
 * The coding style deliberately attempts to ape the format and
 * layout of the AESCrypt.c and AESCrypt.java open source versions
 * this allows for parallel development if AESCrypt format changes
 * This class provides methods to encrypt and decrypt files using
 * http://www.aescrypt.com/aes_file_format.html aescrypt file format
 * version 1 or 2
 *
 *  Copyright (C) 2013 IgoAtM
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details at:
 * http://www.gnu.org/copyleft/lesser.html
 *
*/
// PHP or Personal Home Pages is ever evolving and openssl is replacing mcrypt as the encryption engine
// of choice from 7.2 mcrypt is no more. The problem is pre 5.4 mcrypt dominated hence the selection
// statments based upon version
if (!defined('PHP_VERSION_ID')) {
  $version = explode('.', PHP_VERSION);
  define('PHP_VERSION_ID', ($version[0] * 10000 + $version[1] * 100 + $version[2]));
}

class AESCrypt{
// copy of java declerations
    const DIGEST_ALG = MHASH_SHA256;// hash compatible with c.aes and java-"SHA-256"
    const CRYPT_ALG = MCRYPT_RIJNDAEL_128;//MCRYPT_RIJNDAEL_256;// java-"AES";

    const SSL_CRYPT_ALG = "AES-256-CBC";// openssl required compatibility mode
#    const SSL_OPT = OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING;// cannot use bitwise or | pre php 5.3 so
    const SSL_OPT = 03;// really OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING openssl required compatibility options
#    const CRYPT_TRANS = "AES/CBC/NoPadding";// java-"AES/CBC/NoPadding"
#    const DEFAULT_MAC = "0x010x230x450x670x890xab0xcd0xef";
    const KEY_SIZE = 32; // Note requirements of key size to allow AES compatibility
    const BLOCK_SIZE = 16; // final data must be padded to a whole block size
    const SHA_SIZE = 32;
    const PAD_BLOCK = 0; // padding characters
// valid extension type vectors
    const CREATED_BY = 0;
    const CREATED_DATE = 1;
    const CREATED_TIME = 2;

    protected $password; //
    protected $passfile;
    protected $exttext = array(
      self::CREATED_BY => 'AESCrypt 4 PHP ver 0.6.0'
    );

    protected $etype = array(
      self::CREATED_BY => 'CREATED_BY',
      self::CREATED_DATE => 'CREATED_DATE',
      self::CREATED_TIME => 'CREATED_TIME'
    );

    protected $hmac; // Mac
    protected $random; // SecureRandom
    protected $digest; // MessageDigest
    protected $oIV; // IvParameterSpec
    protected $oAESKey; // SecretKeySpec
    protected $iIV; // IvParameterSpec
    protected $iAESKey; // SecretKeySpec
    protected $mode = 'cbc';//MCRYPT_MODE_CBC;//'cbc'


    function __construct($password){
      if( isset($password) ){
        if( is_file( $password ))
          $this->passfile = $password;
        else
          $this->setPassword($password);
      }
    }


//
/*
 *  Generate a type 2 AESCrypt style header file a clone of aescrypt.c (the java version has a limited empty entry insertion)
 *
 *  Note to retain compatibility between native PHP RIJNDAEL and AES used in c.aes and java versions
 *  must use block size of 16 byte blocks equivalent to 128 bit hence MCRYPT_RIJNDAEL_128
 *
 * Current standard aesCrypt extension tags
 * CREATED_BY       This is a developer-defined text string that identifies the software product,
 *                            manufacturer, or other useful information (such as software version).
 * CREATED_DATE  This indicates the date that the file was created. The format of the date string is YYYY-MM-DD.
 * CREATED_TIME   This indicates the time that the file was created. The format of the date string
*                             is in 24-hour format like HH:MM:SS (e.g, 21:15:04). The time zone is UTC.
*/
  protected function _makeheader(){
    $etype = array(
      0 => 'CREATED_BY',
      1 => 'CREATED_DATE',
      2 => 'CREATED_TIME' );
    $mode= 2;// emulation aes mode 0|1|2 Note: not $this->mode
    $header = '';
    // Generate the AES header for this file
    $header .= 'AES'; // bang/MIME
    $header .= chr($mode); // Version 0|1|2 Octet  - 0x02 (Version)
    $header .= chr(0); // File size modulo 16 in least significant bit positions (reserved mode 0 last block padd size)
// add type 2 extensions
    if( 2 == $mode ){
      foreach( $this->exttext as $k => $v){
// Note: Using $k type number. To give text of $type[$k] . cho(0) . $v as full extension
// maybe need to try to persuade AESCrypt to use option of type numbers (hex) here so can offer translation
// of extensions define via decrypting/encrypting engine
// means real length must be less than 256 - (strlen($type[$k])+1+strlen($v) )
        $elen = strlen($etype[$k] )+1+strlen($v);
        if( 256 >  $elen ){// 255 is maximum total extension size
          $header .= chr(0).chr($elen); // in net-byte-order (big-endian)
          $header .= $etype[$k] . chr(0) . $v;
        }else{
          trigger_error( "extension string too long [".$etype[$k]." $v] length[".(strlen($etype[$k])+1+strlen($v))."]" ,E_USER_WARNING);
        }
      }
    }
// free access small extension area 128 byte block for any data that can be altered without rebuilding file
    $header .= chr(0);
    $header .= chr(128);
    $header .= str_repeat(chr(0),128);
    $header .= chr(0).chr(0); // no further extensions marker
    return $header;
  }

/*
 *  Should not be needed in the php ver as random generation
 *  is catered for with mt_rand.
 *  differences in source code method will not break compatibility
 *  if the requirement is just for random numbers as long as the
 *  result range is emulated
 *  SHA256 digest over given byte array and random bytes.
 *  bytes.length * num  random bytes are added to the digest.
 *
 *  The generated hash is saved back to the original byte array.
 *  Maximum array size is SHA_SIZE bytes. ( 32 )
 */
  protected function _digestRandomBytes( &$bytes, $num) {
    $digest='';
    if(strlen($bytes) > self::SHA_SIZE )
      trigger_error("bad byte size encryption will likley fail", E_USER_ERROR);
    for ($i = 0; $i < $num; $i++){
      for($j = 0; $j < strlen($bytes); $j++)
        $bytes[$j] = chr(mt_rand(0,255));#(substr($bytes, $j, 1));
        $digest = mhash( self::DIGEST_ALG, $bytes );
    }
    $bytes = substr($digest, 0, strlen($bytes));
  }

/*
 * Generates the random AES key used to crypt file contents.
 * @return AES key of KEY_SIZE bytes. (32)
 *  by generating a 32 byte key retains compatibility with AES and php MCRYPT_RIJNDAEL_128
*/
  protected function _generateInnerAESKey() {
    $iv='';
// standard random character string generator
    for($i = 0; $i < self::KEY_SIZE; $i++)
      $iv .= chr(mt_rand(0,255));
    return $iv;
  }

/*
 *  Generates a pseudo-random IV
 *  replacement for native java code not using MAC may alter to include time
 *  CBC mode requires this initialization vector.  The size of the IV (initialization
 * vector) is always equal to the block-size for AES this is fixed to 128 bit or 16 byte
 * Not key-size which defines the encryption depth
 * -- from java based on time and this computer's MAC. and c --
 * using php default mcrypt_create_iv forced to change as mcrypt removed in php 7.2
 *
 * This IV is used to crypt IV 2 and AES key 2 in the file.
 * @return IV.
*/
  protected function _generateOuterIV() {
// php Muppeters are depreciating mcrypt so go native
//    return mcrypt_create_iv(self::BLOCK_SIZE, self::DIGEST_ALG);
    $iv='';
// standard random character string generator
    for($i = 0; $i < self::BLOCK_SIZE; $i++)
      $iv .= chr(mt_rand(0,255));
    return $iv;
  }

/*
 * Generates an oAESKey starting with oIV and applying the supplied user password.
 * This AES key is used to crypt iIV  and iAESKey.
 * @return AES key of KEY_SIZE ( 32 byte - 256 bit )
 *  tests as -- compliant with block sized key length c.aes and Java
 */
  protected function _generateOuterAESKey( $iv, $password){
    $aesKey = $iv . str_repeat(chr(0), (32-strlen($iv) ));
    for ( $i = 0; $i < 8192; $i++) {//
      $aesKey = mhash( self::DIGEST_ALG, $aesKey . $password);
   }
    return $aesKey;
  }

/*
 * Generates the random IV used to crypt file contents.
 * standard random character string generator this can be
 * expounded upon if desired
 * @return IV 2. of BLOCK_SIZE bytes (16)
*/
  protected function _generateInnerIV(){
    $iv='';
//
    for($i = 0; $i < self::BLOCK_SIZE; $i++)
      $iv .= chr(mt_rand(0,255));
    return $iv;
  }

/*
 *  used for openssl
 *  adds padding type PAD_BLOCK
 *  padd to native block size (default)
 *  for AES this will always be 128bit 16byte blocks
 *  or to defined $blocksize
*/
  protected function _addpadding($string, $blocksize = self::BLOCK_SIZE){
    $len = strlen($string);
    $pad = $blocksize - ($len % $blocksize);
    $string .= str_repeat(chr(self::PAD_BLOCK), $pad);
    return $string;
  }


/*
 * Set the user entered password
 * converts format to single byte UTF-16LE if UTF-8
 * Note: uses little-endian for conversion from UTF-8 as required value resides in lsb of word
*/
  public function setPassword($password){
    $this->password = mb_convert_encoding($password, "UTF-16LE", "UTF-8");// tested to match aescrypt format for passwd
  }

/*
 * Builds extension text array after checking for valid inputs
 * requires an array of extension values
 * int key = valid extension type
 * str value = "the extension user added text"
 * total size of the expounded key+value+1 must be less
 * than 255 single byte characters
 * if all above satisfied will enter into AES header on next
 * encrypt until cleared
 * Note keys are unique so will overwrite data to existing
 * key values
*/
  public function setExtText($ext){
    if(!isset($ext) || !is_array($ext)){
      trigger_error( "WARN: ext invalid format. ext must an array", E_USER_WARNING);
      return false;
    }
    foreach( $ext as $k => $v ){
      if(!empty($this->etype[$k]) && 256 > strlen($this->etype[$k] )+1+strlen($v) ){
        $this->exttext[$k] = $v;
      }else{
        if(empty($this->etype[$k])){
          trigger_error("WARN: Not a valid extension type [$k]", E_USER_WARNING);
        }else{
          trigger_error("WARN: extension is too big", E_USER_WARNING);
        }
        return false;
      }
    }
  }

/*
 * The $data is encrypted and returned in encrypted form.
 *
*/
  public function encrypt( $data ){
    if( empty($this->password) )
      return false;
    if(empty($data))
      return false;
    $out='';
// as openssl is adding padding then need block size prior to padding
    $datalen = strlen($data);
// need block size padding if running openssl
    $data = $this->_addpadding($data);
// generate a valid version 2 aesCrypt header
    $out .= $this->_makeheader();
// generate the outer IV (oIV)used for password and inner IV hashing
    $oIV = $this->_generateOuterIV(); // CRYPT_ALG
// generate the outer Key (oAESKey) using supplied password hashing with oIV
    $oAESKey =$this->_generateOuterAESKey( $oIV, $this->password );
// generate the encrypted inner IV (iIV) and Key (iAESKey) used for textstring data encryption
    $iIV = $this->_generateInnerIV();
    $iAESKey = $this->_generateInnerAESKey(); // CRYPT_ALG
// Output oIV
    $out .=$oIV;
// encrypt and write out iIV and iAESKey
    if( PHP_VERSION_ID < 50400 ){
      $ivnkey = mcrypt_encrypt( self::CRYPT_ALG, $oAESKey,  $iIV.$iAESKey, MCRYPT_MODE_CBC, $oIV );
    }else{
      $ivnkey = openssl_encrypt($iIV.$iAESKey, self::SSL_CRYPT_ALG, $oAESKey, self::SSL_OPT, $oIV);
    }
    $out .= $ivnkey;
// generate HMAC for iIV and iAESKey1
    $hmac = mhash( self::DIGEST_ALG, $ivnkey, $oAESKey);
    $out .= $hmac;
// hash the textstring data using the inner IV and Key
    if( PHP_VERSION_ID < 50400 ){
      $ctext = mcrypt_encrypt( self::CRYPT_ALG, $iAESKey, $data, MCRYPT_MODE_CBC, $iIV );
    }else{
      $ctext = openssl_encrypt($data, self::SSL_CRYPT_ALG, $iAESKey, self::SSL_OPT, $iIV);
    }
    $out .= $ctext;
// mark the last whole block size use the real data length not padded
    $out .= chr($datalen %16);
// generate the HMAC for the textstring data
    $cmac = mhash( self::DIGEST_ALG, $ctext, $iAESKey);
    $out .= $cmac;
    return $out;
  }

 /*
 * AESCrypt decrypt
 * The $data is decrypted and returned in un-encrypted form.
 * fails return false
 *
 * version can be either 1 or 2
 *
 *
 *
*/
  public function decrypt($data) {
// check data exists and has file bang/MIME
    if(!isset($data) || 'AES' !== substr($data,0,3) ){
      trigger_error("decrypt called with none AES headed file", E_USER_ERROR);
      return false;
    }
// The AES Version code byte 0 | 1 | 2
    $mode=ord(substr($data,3,1));
    if(3 < $mode ){
      trigger_error("AES mode [$mode] unsupported", E_USER_ERROR);
      return false;
    }
// If mode = 0 or 1 then? Problem is generating mode 0 and 1 files
// for testing. For now assume mode is 2
    $ptr=4;
// For now skip past all header extensions
// may decide to act on if flagged for situations like say extract all after date
// or only process if user name is or or ...? or
    if( 2 == $mode ){
      if(138 > strlen($data) ){
        trigger_error("file is too short [".strlen($data)."] for a AES mode 2 file", E_USER_ERROR);
        return false;
      }
      while($ptr < strlen($data) ){
        $ptr++;
        $len = ord($data[$ptr])+ord($data[$ptr+1]);
#        $ext = substr($data,$ptr+2,$len); // extension string available if required
        $ptr = $ptr + ord($data[$ptr+1])+1;
        if(0 == $len){// found our 0000 end of ext marker
          break;
        }
        else{ // if response is required to ext this is where they would go ?
          true;//echo "\nuse it or loose it [$ext]\n";
        }
      }
    }
// ptr+1 = 16 Octets - Initialisation Vector (IV) used for encrypting the IV and symmetric key
// that is actually used to decrypt the bulk of the plaintext file.
    $ptr++;
    $oIV=substr($data, $ptr, 16);// the oIV from the cipher
    $oAESKey = $this->_generateOuterAESKey( $oIV, $this->password);// use the cipher oIV and password to generate oAESKey
    $ptr = $ptr+16;
// 48 Octets - Encrypted IV and 256-bit AES key used to encrypt the bulk of the file
// comprising 16 octets - initialisation vector 32 octets - encryption key
    $iIV = substr($data, $ptr, 16);// cipher iIV
    $ptr = $ptr+16;
    $iAESKey = substr($data, $ptr, 32);// cipher iAESKey
    $ptr = $ptr+32;
// decrypt the cipher iIV IAESKey with the cipher oIV Using the user input password generated oAESKey
    if( PHP_VERSION_ID < 50400 ){
      $ivnkey = mcrypt_decrypt( self::CRYPT_ALG, $oAESKey,  $iIV.$iAESKey, MCRYPT_MODE_CBC, $oIV );
    }else{
      $ivnkey = openssl_decrypt( $iIV.$iAESKey, self::SSL_CRYPT_ALG, $oAESKey, self::SSL_OPT, $oIV );
    }
//32 Octets - HMAC
    $ohmac = substr($data, $ptr, 32); // data HMAC cipher (iIV iAESKey) HMAC must match
    $xhmac = mhash( self::DIGEST_ALG, $iIV.$iAESKey, $oAESKey);// HMAC generated using oAESKey made using user password
    if($ohmac != $xhmac){
      trigger_error("HMAC mismatch the password is incorrect or the message is corrupt",E_USER_WARNING);
      return false;
    }
    $ptr = $ptr+32;// for version 2 files ptr should now be at start of ciphertext
// recover hashed iIV and iAESKey
    $iIV = substr($ivnkey,0,16);
    $iAESKey = substr($ivnkey,16,32);
// last block offset
    $lbo = ord(substr($data,strlen($data)-33, 1));
// main encrypted ciphertext ends 33 bytes less than the length of data
// 1 byte last block offset and 32 byte inner HMAC
    $buffer = substr($data, $ptr, -33);
// ciphertext HMAC
    $xhmac = substr($data,strlen($data)-32, 32);
// generate the HMAC for the textstring data
    $cmac = mhash( self::DIGEST_ALG, $buffer, $iAESKey);
    if($cmac != $xhmac){
      trigger_error("HMAC the message is corrupt",E_USER_WARNING);
      return false;
    }
    if( PHP_VERSION_ID < 50400 ){
      $ctext = mcrypt_decrypt( self::CRYPT_ALG, $iAESKey, $buffer, MCRYPT_MODE_CBC, $iIV );
    }else{
      $ctext = openssl_decrypt( $buffer, self::SSL_CRYPT_ALG, $iAESKey, self::SSL_OPT, $iIV );
    }
    $ptr = strlen($data)-32;
    $lastblock = substr($data, $ptr, 1);
// output trimming added the first version stayed true to the clone of aescrypt
// which also did not tidy up last block overspill but it has since been changed
// so likewise this now removes block padding to real file length
    return trim($ctext);
  }


  public function test(){
// test what ??
    $output= '';
    $output.= $this->_makeheader();
    $output.= $this->_generateOuterAESKey($this->_generateInnerIV(), 'plop');
    return $output;
  }

}
/* to disable the test delete leading backslash '/'
$fname='IgoAtM_AES_Test_Data.txt';
$test_pw = 'pl0pwazear';

$testdata = "This is auto generated test data
for testing the encryption and decryption of
class.aesCrypt.php.
If you have run this via a php cli
using a terminal then in reading this
you know that this massage has been
encrypted and decrypted OK. It will have
left some files behind wherever this class
has been located
IgoAtM_AES_Test_Data.txt
and
IgoAtM_AES_Test_Data.txt.aes
the above .aes file can be used to check
compatibility with the c version of aesCrypt program
from http://www.aescrypt.com
the password used to encrypt was " . $test_pw . "
to disable this test delete the leading backslash '/'
as commented at the bottom of the class file or just
delete the comment block";


file_put_contents( $fname, $testdata );

$data=file_get_contents($fname);
$aes = new AESCrypt($test_pw);
# setPassword is not required but can be used if password is altered
# during say multiple file encryption decryption
# $aes->setPassword('pl0pwazeara5well');
$aes->setExtText(array(
  $aes::CREATED_DATE=>'The date is 11/12/13',
  $aes::CREATED_BY=>"aesCrypt clone in php"
  )
);
file_put_contents($fname . '.aes', $aes->encrypt( $data) );
$data=file_get_contents($fname . '.aes');
echo $aes->decrypt($data);
// */

?>
