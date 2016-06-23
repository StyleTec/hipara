rule test 
{
	meta:
		filetype = "doc"
		date = "2014-09-16"
		description = "word document containing Frank Doe"
		version = "1.0"
	strings:
		$a = "Frank Doe" 
	condition:
		any of them
}
