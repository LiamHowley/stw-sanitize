(defsystem #:stw-sanitize-test
  :description "Test suite for STW-SANITIZE"
  :depends-on ("stw-xml-parse"
	       "stw-html-parse"
	       "stw-sanitize"
	       "parachute")
  :components ((:file "package")
	       (:file "test"))
  :perform (asdf:test-op (op c) (uiop:symbol-call :parachute :test :sanitize.test)))
