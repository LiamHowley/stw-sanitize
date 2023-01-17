(defsystem #:stw-sanitize
  :license "MIT"
  :author "Liam Howley <liam.howley@thespanningtreeweb.ie>"
  :description "A whitelisting library for sanitizing user input."
  :depends-on ("stw-xml-parse"
	       "stw-html-parse"
	       "closer-mop"
	       "stw-utils"
	       "cl-comp"
	       "quri")
  :serial t
  :components ((:file "package")
	       (:file "meta")
	       (:file "mode")
	       (:file "sanitize"))
  :long-description
  #.(uiop:read-file-string
     (uiop:subpathname *load-pathname* "docs/README.org"))
  :in-order-to ((test-op (load-op :stw-sanitize-test))))
