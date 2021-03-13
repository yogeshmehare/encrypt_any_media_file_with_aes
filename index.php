<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Primary Meta Tags -->
    <title>Welcome to SecureMe</title>
    <meta name="title" content="Welcome to SecureMe">
    <meta name="description" content="File Encryption/Decryption Made easy With AESfileCrypt.">

    <!-- Open Graph / Facebook -->
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://securem3.000webhostapp.com/">
    <meta property="og:title" content="Welcome to SecureMe">
    <meta property="og:description" content="File Encryption/Decryption Made easy With AESfileCrypt.">
    <meta property="og:image" itemprop="image" content="logo.png">

    <!-- Twitter -->
    <meta property="twitter:card" content="summary_large_image">
    <meta property="twitter:url" content="https://securem3.000webhostapp.com/">
    <meta property="twitter:title" content="Welcome to SecureMe">
    <meta property="twitter:description" content="File Encryption/Decryption Made easy With AESfileCrypt.">
    <meta property="twitter:image" content="logo.png">
    <title>Upload!</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.8.0/css/bulma.min.css">
    <link href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet" integrity="sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN" crossorigin="anonymous">
    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
    <style>
    .center {
      margin: 0;
      position: absolute;
      top: 50%;
      left: 50%;
      -ms-transform: translate(-50%, -50%);
      transform: translate(-50%, -50%);
    }
    </style>
  </head>
  <body>

<section class="hero is-dark is-medium">
  <div class="hero-head">
    <header class="navbar">
      <div class="container">
        <div class="navbar-brand">
          <a href="index.php" class="navbar-item">
            <img src="logo2.png" alt="Logo">
          </a>
          <span class="navbar-burger burger" data-target="navbarMenuHeroC">
            <span></span>
            <span></span>
            <span></span>
          </span>
        </div>
        <div id="navbarMenuHeroC" class="navbar-menu">
          <div class="navbar-end">
            <a class="navbar-item is-active">
              Home
            </a>
            <a href="https://twitter.com/abhijeet__911" class="navbar-item">
                <span class="icon">
                  <i class="fab fa-twitter"></i>
                </span>
                <span>@abhijeet__911</span>
            </a>
            <span class="navbar-item">
              <a href="https://github.com/abhijeetsatpute" class="button is-dark is-inverted">
                <span class="icon">
                  <i class="fab fa-github"></i>
                </span>
                <span>GitHub</span>
              </a>
            </span>
          </div>
        </div>
      </div>
    </header>
  </div>


      <div class="container hero-body">
        <div class="container">
          <h1 style="font-size:45px;" class="title">
             Welcome to SecureMe
          </h1>
          <h2 class="subtitle">
            Easy file encryption with one click
          </h2>
        </div>
      </div>
</section>

<section class="hero">
  <div class="container hero-body">
	     <form class="container" method="POST" action="upload.php" enctype="multipart/form-data">
			      <div class="field">
				          <div class=" file has-name">
				                <label class="file-label">
					                   <input type="file" name="file" class="file-input">
					                          <span class="file-cta">
					                                     <span class="file-icon ">
						                                           <i class="fas fa-upload"></i>
					                                     </span>
					                                     <span class="file-label">
						                                            Choose a file...
					                                     </span>
					                           </span>
					                          <span class="file-name button is-info is-outlined">
					                                 Waiting for choice...
					                         </span>
				                </label>
			   	       </div>
			    </div>
  </div>
    			<div class="container is-grouped">
    		      <div class="control center">
    			         <input class="button is-success is-outlined" type="submit" value="Upload">
    		      </div>
		     </div>

	  </form>


<div class="table-container hero-body">
   <table class="container table  is-bordered" cellspacing="0" cellpadding="0">
     <?php
     // This will return all files in that folder
     $files = scandir("uploads");

     if (!isset($files[2])) {
      print('<h2 class="notification" align="center">No files uploaded</h2>');
     }
      ?>
      <thead>
        <tr class="is-selected">
        <th><h1>File</h1></th>
        <th><h1>Encrypt</h1></th>
        <th><h1>Decrypt</h1></th>
        <th><h1>Delete</h1></th>
        </tr>
      </thead>
      <?php


      // If you are using windows, first 2 indexes are "." and "..",
      // if you are using Mac, you may need to start the loop from 3,
      // because the 3rd index in Mac is ".DS_Store" (auto-generated file by Mac)

      for ($a = 2; $a < count($files); $a++)
      {
      ?>

       <tbody>
           <tr>
              <!-- Displaying file name !-->
              <!-- href should be complete file path !-->
              <!-- download attribute should be the name after it downloads !-->
              <td><a href="uploads/<?php echo $files[$a]; ?>" download="<?php echo $files[$a]; ?>">
                  <?php  echo $files[$a]; ?>
              </a></td>
              <td><a href="AES-enc.php?name=uploads/<?php echo $files[$a] ?>" style="color: green;">
                    Encrypt
                  </a>
              </td>
              <td><a href="AES-dec.php?name=uploads/<?php echo $files[$a]; ?>" style="color: black;">
                   Decrypt
                   </a>
              </td>
              <td><a href="delete.php?name=uploads/<?php echo $files[$a]; ?>" style="color: red;">
                  Delete
                  </a>
              </td>
            </tr>
       </tbody>


<?php
}
?>
</table>
</div>
</section>
</body>

<script src="main.js"></script>
<script>

  function myFunction() {
    var txt;
    var password = prompt("Please enter the password for your file:", "Password123");
    if (password == null || password == "") {
      alert("Enter a valid password");
    }
    return password;
  }

	document.addEventListener('DOMContentLoaded', () => {
	  // 1. Display file name when select file
	  let fileInputs = document.querySelectorAll('.file.has-name')
	  for (let fileInput of fileInputs) {
		let input = fileInput.querySelector('.file-input')
		let name = fileInput.querySelector('.file-name')
		input.addEventListener('change', () => {
		  let files = input.files
		  if (files.length === 0) {
			name.innerText = 'No file selected'
		  } else {
			name.innerText = files[0].name
		  }
		})
	  }
	})
</script>

</html>
