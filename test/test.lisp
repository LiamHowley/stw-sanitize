(in-package sanitize.test)


(defparameter *basic-html*
  "<b>Lo<!-- comment -->rem</b> <a href=\"pants\" title=\"foo\">ipsum</a> <a href=\"http://foo.com/\"><strong>dolor</strong></a> sit<br/>amet <script>alert(\"hello world\");</script>")

(define-test basic
    :parent scour
  (is string= "Lorem ipsum dolor sitamet alert(&quot;hello world&quot;);"
      (sanitize *basic-html* (find-class 'text-only) :mode :silent))

  (is string= "<b>Lorem</b> ipsum <strong>dolor</strong> sitamet alert(&quot;hello world&quot;);"
      (sanitize *basic-html* (find-class 'restricted) :mode :silent))

  (is string= "<b>Lorem</b> <a href='pants' rel='nofollow'>ipsum</a> <a href='http://foo.com/' rel='nofollow'><strong>dolor</strong></a> sit<br />amet alert(&quot;hello world&quot;);"
      (sanitize *basic-html* (find-class 'basic) :mode :silent))

  (is string= "<b>Lorem</b> <a title='foo' href='pants'>ipsum</a> <a href='http://foo.com/'><strong>dolor</strong></a> sit<br />amet alert(&quot;hello world&quot;);"
      (sanitize *basic-html* (find-class 'relaxed) :mode :silent)))

;;; malformed

(defparameter *malformed-html*
  "Lo<!-- comment -->rem</b> <a href=pants title=\"foo>ipsum <a href=\"http://foo.com/\"><strong>dolor</a></strong> sit<br/>amet <script>alert(\"hello world\");")

(define-test malformed
  :parent scour
  (is string= "Lorem dolor sitamet alert(&quot;hello world&quot;);"
      (sanitize *malformed-html* (find-class 'text-only) :mode :silent))

  (is string= "Lorem <strong>dolor</strong> sitamet alert(&quot;hello world&quot;);"
      (sanitize *malformed-html* (find-class 'restricted) :mode :silent))

  (is string= "Lorem <a href='pants' rel='nofollow'><strong>dolor</strong></a> sit<br />amet alert(&quot;hello world&quot;);"
      (sanitize *malformed-html* (find-class 'basic) :mode :silent))

  (is string= "Lorem <a title='foo&gt;ipsum &lt;a href=' href='pants'><strong>dolor</strong></a> sit<br />amet alert(&quot;hello world&quot;);"
      (sanitize *malformed-html* (find-class 'relaxed) :mode :silent))

  (is string= "Lorem <a title='foo&gt;ipsum &lt;a href=' href='pants'><strong>dolor</strong></a> sit<br />amet alert(&quot;hello world&quot;);"
      (sanitize *malformed-html* (find-class 'relaxed))))


;;; unclosed

(defparameter *unclosed-html*
  "<p>a</p><blockquote>b")

(define-test unclosed
    :parent scour
  (is string= "ab"
      (sanitize *unclosed-html* (find-class 'text-only)))

  (is string= "ab"
      (sanitize *unclosed-html* (find-class 'restricted)))

  (is string= "<p>a</p><blockquote>b</blockquote>"
      (sanitize *unclosed-html* (find-class 'basic)))

  (is string= "<p>a</p><blockquote>b</blockquote>"
      (sanitize *unclosed-html* (find-class 'relaxed))))


;;; malicious

(defparameter *malicious-html*
  "<b>Lo<!-- comment -->rem</b> <a href=\"javascript:pants\" title=\"foo\">ipsum</a> <a href=\"http://foo.com/\"><strong>dolor</strong></a> sit<br/>amet <<foo>script>alert(\"hello world\");</script>")

(define-test malicious
  :parent scour
  (is string= "Lorem ipsum dolor sitamet &lt;script&gt;alert(&quot;hello world&quot;);"
      (sanitize *malicious-html* (find-class 'text-only) :mode :silent))

  (is string= "<b>Lorem</b> ipsum <strong>dolor</strong> sitamet &lt;script&gt;alert(&quot;hello world&quot;);"
      (sanitize *malicious-html* (find-class 'restricted) :mode :silent))

  (is string= "<b>Lorem</b> <a rel='nofollow'>ipsum</a> <a href='http://foo.com/' rel='nofollow'><strong>dolor</strong></a> sit<br />amet &lt;script&gt;alert(&quot;hello world&quot;);"
      (sanitize *malicious-html* (find-class 'basic) :mode :silent))

  (is string= "<b>Lorem</b> <a title='foo'>ipsum</a> <a href='http://foo.com/'><strong>dolor</strong></a> sit<br />amet &lt;script&gt;alert(&quot;hello world&quot;);"
      (sanitize *malicious-html* (find-class 'relaxed) :mode :silent))

  (is string= "<b>Lorem</b> <a title='foo'>ipsum</a> <a href='http://foo.com/'><strong>dolor</strong></a> sit<br />amet &lt;&lt;foo&gt;script&gt;alert(&quot;hello world&quot;);"
      (sanitize *malicious-html* (find-class 'relaxed))))

  ;; When mode is strict, as by default, the errors CLASS-NOT-FOUND-ERROR
  ;; and STRAY-CLOSING-TAG-ERROR are invoked, and are handled respectively by
  ;; the restart ASSIGN-TEXT-NODE, and CLOSE-NODE. This allows for strings
  ;; that have a valid #\< character placed in a sequence or for demonstration
  ;; purposes. So for example <test> will parse as &lt;test&gt; but </test> will
  ;; be removed. To whit:

(define-test errant-<-tag
  :parent scour
  (is string= "&lt;test&gt;" (sanitize "<test>" (find-class 'relaxed)))
  (is string= "OMG HAPPY BIRTHDAY! *&lt;:-D" (sanitize "OMG HAPPY BIRTHDAY! *<:-D" (find-class 'relaxed))))



;;; raw-comment

(defparameter *comment-html* "Hello, <!-- comment -->World!")

(define-whitelist relaxing-with-comments (relaxed)
  ((!-- :content "the-content")))

(define-test comments
    :parent scour
  (is string= "Hello, World!"
      (sanitize *comment-html* (find-class 'text-only) :mode :silent))

  (is string= "Hello, World!"
      (sanitize *comment-html* (find-class 'restricted) :mode :silent))

  (is string= "Hello, World!"
      (sanitize *comment-html* (find-class 'basic) :mode :silent))

  (is string= "Hello, World!"
      (sanitize *comment-html* (find-class 'relaxed) :mode :silent))

  (is string= *comment-html*
      (sanitize *comment-html* (find-class 'relaxing-with-comments) :mode :silent)))


(defparameter *conditional-injection*
  "<!--[if gte IE 4]>\n<script>alert('XSS');</script>\n<![endif]-->")

(define-test conditionals
    :parent scour
  (is string= ""
      (sanitize *conditional-injection* (find-class 'text-only)))

  (is string= ""
      (sanitize *conditional-injection* (find-class 'restricted)))

  (is string= ""
      (sanitize *conditional-injection* (find-class 'basic)))

  (is string= ""
      (sanitize *conditional-injection* (find-class 'relaxed))))


;;; protocol-based JS injection: simple, no spaces

(defparameter *js-injection-html-1*
  "<a href=\"javascript:alert(\'XSS\');\">foo</a>")

;;; protocol-based JS injection: simple, spaces before
(defparameter *js-injection-html-2*
  "<a href=\"javascript    :alert(\'XSS\');\">foo</a>")

;;; protocol-based JS injection: simple, spaces after
(defparameter *js-injection-html-3*
  "<a href=\"javascript:    alert(\'XSS\');\">foo</a>")

;;; protocol-based JS injection: simple, spaces before and after
(defparameter *js-injection-html-4*
  "<a href=\"javascript    :   alert(\'XSS\');\">foo</a>")

;;; protocol-based JS injection: preceding colon
(defparameter *js-injection-html-5*
  "<a href=\":javascript:alert(\'XSS\');\">foo</a>")

;;; protocol-based JS injection: UTF-8 encoding
(defparameter *js-injection-html-6*
  "<a href=\"javascript&#58;\">foo</a>")

;;; protocol-based JS injection: long UTF-8 encoding
(defparameter *js-injection-html-7*
  "<a href=\"javascript&#0058;\">foo</a>")

;;; protocol-based JS injection: long UTF-8 encoding without semicolons
(defparameter *js-injection-html-8*
  "<a href=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>foo</a>")

;;; protocol-based JS injection: hex encoding
(defparameter *js-injection-html-9*
  "<a href=\"javascript&#x3A;\">foo</a>")

;;; protocol-based JS injection: long hex encoding
(defparameter *js-injection-html-10*
  "<a href=\"javascript&#x003A;\">foo</a>")

;;; protocol-based JS injection: hex encoding without semicolons
(defparameter *js-injection-html-11*
  "<a href=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>foo</a>")

(defparameter *js-injection-html-12*
  "<h1 onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")></h1>")

(defparameter *js-injection-html-13*
  "<h1 onload=alert(\"XSS\")></h1>")

;; with grave characters
(defparameter *js-injection-html-14*
  "<img src=`javascript:alert('XSS')`>")

;; Encoded carriage return.
(defparameter *js-injection-html-15*
"<img src=\"jav&#x0D;ascript:alert('XSS');\">")

;; Encoded tab character.
(defparameter *js-injection-html-16*
"<img src=\"jav&#x09;ascript:alert('XSS');\">")

;; Encoded newline.
(defparameter *js-injection-html-17*
"<img src=\"jav&#x0A;ascript:alert('XSS');\">")

;; Null byte.
(defparameter *js-injection-html-18*
"<img src=java\0script:alert(\"XSS\")>")

;; Spaces plus meta char.
(defparameter *js-injection-html-19*
"<img src=\" &#14;  javascript:alert('XSS');\">")

;; Mixed spaces and tabs.
(defparameter *js-injection-html-20*
"<img src=\"j\na v\tascript://alert('XSS');\">")

(define-test js-injection-encodings
  :parent scour
  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-1* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-2* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-3* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-4* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-5* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-6* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-7* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-8* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-9* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-10* (find-class 'relaxed) :mode :silent))

  (is string= "<a>foo</a>"
      (sanitize *js-injection-html-11* (find-class 'relaxed) :mode :silent))

  (is string= "<h1></h1>"
      (sanitize *js-injection-html-12* (find-class 'relaxed) :mode :silent))

  (is string= "<h1></h1>"
      (sanitize *js-injection-html-13* (find-class 'relaxed) :mode :silent))

  (is string= "<img />"
      (sanitize *js-injection-html-14* (find-class 'relaxed) :mode :silent))

  (is string= "<img />"
      (sanitize *js-injection-html-15* (find-class 'relaxed) :mode :silent))

  (is string= "<img />"
      (sanitize *js-injection-html-16* (find-class 'relaxed) :mode :silent))

  (is string= "<img />"
      (sanitize *js-injection-html-17* (find-class 'relaxed) :mode :silent))

  (is string= "<img />"
      (sanitize *js-injection-html-18* (find-class 'relaxed) :mode :silent))

  (false (string= "<img />"
		 (sanitize *js-injection-html-19* (find-class 'relaxed) :mode :silent)))

  (is string= "<img />"
      (sanitize *js-injection-html-19* (find-class 'relaxed)))

  (is string= "<img />"
      (sanitize *js-injection-html-20* (find-class 'relaxed))))
