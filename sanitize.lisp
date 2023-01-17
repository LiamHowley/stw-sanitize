(in-package sanitize)


(defmethod whitelist-rules ((class element-class) (whitelist-node whitelist))
  (let ((element (class->element class)))
    (element->slot element whitelist-node)))

(declaim (inline prep-link))

(defun prep-link (link)
  (remove-if #'whitespacep (string-left-trim '(#\` #\:) link)))


(defmethod match-attribute ((slot xml-direct-slot-definition) (rule whitelist-rule))
  (let ((slot-attribute (slot-definition-attribute slot)))
    (loop
      for attribute in (slot-value rule 'attributes)
      do (typecase attribute
	   ((or symbol string)
	    (when (string= slot-attribute attribute)
	      (return t)))
	   (cons
	    (when (string= slot-attribute (car attribute))
	      (return #'(lambda (value)
			  (awhen (getf (cdr attribute) :protocols)
			    (let* ((uri (uri (prep-link value)))
				   (scheme (uri-scheme uri))
				   (path (uri-path uri)))
			      (if scheme
				  (member scheme self :test #'string-equal)
				  (and path
				       (member "relative" self :test #'string-equal)))))))))))))


(defun add-attributes (node whitelist-rules)
  (loop
    for (attribute . value) in (slot-value whitelist-rules 'add-attributes)
    for slot = (attribute->slot attribute (class-of node))
    do (awhen (slot-definition-name slot)
	 (setf (slot-value node self) value))))
	  

(defun filter (whitelist-node)
  #'(lambda (node)
      (and (typep node 'dom-node)
	   (awhen (whitelist-rules (class-of node) whitelist-node)
	     (add-attributes node self)
	     #'(lambda (slot value)
		 (awhen (match-attribute slot self)
		   (etypecase self
		     (boolean t)
		     (function (funcall self value)))))))))
	   

(declaim (inline whitelist-parser))

(defun whitelist-parser (string whitelist-node class-map)
  (parse-document string
		  :parser #'read-fragment
		  :preserve-whitespace t
		  :element-class-map class-map
		  :filter (filter whitelist-node)))

(defun sanitize
    (string whitelist-node
     &key
       (class-map *html-element-class-map*)
       (mode :strict)
       (on-class-not-found #'assign-text-node)
       (on-stray-closing-tag #'close-node)
       (on-tag-mismatch #'close-node))
  (let ((*mode* mode))
    (handler-bind ((class-not-found-error on-class-not-found)
		   (slot-not-found-error #'ignore-missing-slot)
		   (tag-mismatch-error on-tag-mismatch)
		   (invalid-xml-character-error #'remove-character)
		   (restricted-xml-character-error #'remove-character)
		   (stray-closing-tag-error on-stray-closing-tag))
      (serialize (whitelist-parser string whitelist-node class-map)))))
