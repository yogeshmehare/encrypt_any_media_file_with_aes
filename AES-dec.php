<?php
	require 'class.aesCrypt.php'; // class
	$test_pw = 'ThisIsMySecretPassphrase';

	// Initializing the class
	$crypt = new AESCrypt($test_pw);

	//$file = 'path/to/my/file/file.txt';
	$file = $_GET["name"];
	$filename = pathinfo($file, PATHINFO_FILENAME);
	$fileExt = explode(".",$file);
	if (end($fileExt)=="aes"){
		// read content
		$data=file_get_contents($file);
		// decrypt and write to a new file (existing file is overwritten)
		file_put_contents('uploads/'.$filename, $crypt->decrypt( $data) );
		unlink($file);
		header("Location: " . $_SERVER["HTTP_REFERER"]);

	} else{
		echo '<script>
					alert("File is not Encrypted.");
					window.location.href="index.php";
					</script>';
	}
?>
