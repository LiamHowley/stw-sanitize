(in-package sanitize)


(defclass whitelist (standard-class)
  ((index :type hash-table
	  :documentation "Hash table that maps element names to slots."
	  :reader index)
   (all-attributes :type list
		   :initarg :all
		   :initform nil
		   :documentation "When an element is whitelisted accept these attributes."
		   :reader whitelisted-attributes)))

(defmethod element->slot ((element string) (class whitelist))
  (with-slots (index) class
    (gethash element index)))

(defmethod shared-initialize :after ((class whitelist) slot-names &key)
  (declare (ignore slot-names))
  (let ((slots (filter-slots-by-type class 'whitelist-rule)))
    (setf (slot-value class 'index) (make-hash-table :test #'equal :size (length slots)))
    (with-slots (index all-attributes) class
      (loop
	for slot in slots
	for element = (slot-value slot 'element)
	for attributes = (slot-value slot 'attributes)
	do (setf (slot-value slot 'attributes) (append attributes all-attributes)
		 (gethash element index) slot)))))


(defmethod validate-superclass ((class whitelist) (super standard-class))
  t)


(defclass whitelist-rule (standard-direct-slot-definition)
  ((element
    :initarg :element
    :type string
    :reader element)
   (attributes
    :initarg :attributes
    :initform nil
    :type list
    :reader attributes)
   (add-attributes
    :initarg :add-attributes
    :initform nil
    :type list)))


(defmethod direct-slot-definition-class ((class whitelist) &key &allow-other-keys)
  (find-class 'whitelist-rule))

(defclass whitelist-effective-slot-definition (standard-effective-slot-definition)
  ())

(defmethod effective-slot-definition-class ((class whitelist) &key &allow-other-keys)
  (find-class 'whitelist-effective-slot-definition))

(defmethod slot-unbound (class (slot whitelist-rule) (slot-name (eql 'element)))
  (declare (ignore class))
  (setf (slot-value slot 'element) (string-downcase (slot-definition-name slot))))

(defmethod shared-initialize :after ((class whitelist-rule) slot-names &key content)
  (declare (ignore slot-names))
  (with-slots (element attributes) class
    (when content
      (pushnew content attributes :test #'string=))
    (unless (stringp element)
      (error "the element ~s is not a string." element))))


(defmacro define-whitelist (name &body parts)
  (let ((supers (car parts))
	(slots (mapcar
		#'(lambda (slot)
		    (when (consp slot)
		      (setf (getf (cdr slot) :attributes)
			    (loop for attribute in (getf (cdr slot) :attributes)
				  collect (ensure-list attribute))
			    (getf (cdr slot) :add-attributes)
			    (loop for attribute in (getf (cdr slot) :add-attributes)
				  collect (ensure-list attribute))))
		    slot)
		(cadr parts)))
	(class-slots (cddr parts)))
    `(progn
       (eval-when (:compile-toplevel :load-toplevel :execute)
	 (defclass ,name ,supers
	   ,slots
	   ,@(unless (assoc :metaclass class-slots)
	       `((:metaclass whitelist)))
	   ,@class-slots)
	 (defmethod shared-initialize ((class ,name) slot-names &key)
	   (declare (ignore slot-names))
	   (error "The class ~a is a singleton and cannot be instantiated" ',name))))))
