<?php
	require 'class.aesCrypt.php'; // class
	$test_pw = 'ThisIsMySecretPassphrase';

	// Initializing the class
	$crypt = new AESCrypt($test_pw);

	// File to encrypt
	//$file = 'path/to/my/file/file.txt';
	$file = $_GET["name"];
	$fileExt = explode(".",$file);
	if (end($fileExt)=="aes"){
		echo '<script>
					alert("File is already Encrypted.");
					window.location.href="index.php";
					</script>';
	} else{
		// read content
		$data=file_get_contents($file);

		// encrypt and write to a new file  (existing file is overwritten)
		file_put_contents($file . '.'.'aes', $crypt->encrypt( $data));
		unlink($file);
		header("Location: " . $_SERVER["HTTP_REFERER"]);
	}
?>
