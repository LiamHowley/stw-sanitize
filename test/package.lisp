(defpackage sanitize.test
  (:use :cl
	:sanitize
	:xml.parse
	:html.parse)
  (:import-from
   :parachute
   :define-test
   :test
   :is
   :false)
  (:export :scour))

(in-package sanitize.test)

(define-test scour)
