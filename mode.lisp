(in-package sanitize)

(define-whitelist text-only
  ())

(define-whitelist restricted
  ()
  (b em i strong u small strike sub sup))


(define-whitelist basic
  (restricted)
  ((a          :attributes (("href" :protocols ("ftp" "http" "https" "mailto" "relative")))
	       :add-attributes (("rel" . "nofollow")))
   (abbr       :attributes ("title"))
   (blockquote :attributes (("cite" :protocols ("http" "https" "relative"))))
   (dfn        :attributes ("title"))
   (q          :attributes (("cite" :protocols ("http" "https" "relative"))))
   (html-time  :element "time" :attributes ("datetime"))
   br cite code dd dl dt kbd li mark ol p pre s samp ul var))


(define-whitelist relaxed
  (basic)
  ((a          :attributes (("href" :protocols ("ftp" "http" "https" "mailto" "relative"))))
   (del        :attributes (("cite" :protocols ("http" "https" "relative"))))
   (img        :attributes (("src"  :protocols ("http" "https" "relative"))))
   (ins        :attributes (("cite" :protocols ("http" "https" "relative"))))
   (col        :attributes ("span" "width"))
   (colgroup   :attributes ("span" "width"))
   (ol         :attributes ("start" "reversed" "type"))
   (table      :attributes ("summary" "width"))
   (td         :attributes ("abbr" "axis" "colspan" "rowspan" "width"))
   (th         :attributes ("abbr" "axis" "colspan" "rowspan" "scope" "width"))
   (ul         :attributes ("type"))
   (font       :attributes ("size"))
   bdo caption figcaption figure h1 h2 h3 h4 h5 h6 hgroup rp rt ruby tbody tfoot thead tr wbr)
  (:all . ("dir" "lang" "title" "class")))
