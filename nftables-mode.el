(require 'rx)
(require 'syntax)                       ; syntax-ppss, for indentation

(defvar nftables-mode-map (make-sparse-keymap))
(defvar nftables-mode-hook nil)
(defvar nftables-mode-syntax-table
  (let ((table (make-syntax-table)))
    (modify-syntax-entry ?# "<\n" table)  ; make #comment work
    (modify-syntax-entry ?\n ">#" table)  ; make #comment work
    (modify-syntax-entry ?_ "w" table)    ; foo_bar is 1 word (not 2)
    table))

;;; NOTE: I started with the keywords in the nano highlighter, but
;;; they were really incomplete.  So instead I looked at the
;;; flex/bison rules in the nft source code (as at debian/0.9.1-2-2-g3255aaa):
;;;     https://salsa.debian.org/pkg-netfilter-team/pkg-nftables/blob/master/src/scanner.l
;;;     https://salsa.debian.org/pkg-netfilter-team/pkg-nftables/blob/master/src/parser_bison.y
;;; NOTE: not supporting multi-statement lines "list ruleset; flush ruleset".
;;; NOTE: not supporting multi-line statements "list \\\n ruleset".
;;; NOTE: not supporting arbitrary whitespace in some places.
;;; NOTE: identifiers are hard (e.g. bare addresses, names, quoted strings), so
;;;       not supporting all those properly.
;;; NOTE: family can be omitted; it defaults to "ip" (IPv4 only).
;;;       I am not supporting that, because you USUALLY want "inet" (IPv4/IPv6 dual-stack).
;;; NOTE: there are two main styles, I'm supporting only those and not a mix of same.
;;;
;;;       Style #1:
;;;
;;;            flush ruleset
;;;            table inet foo {
;;;                chain bar {
;;;                    type filter hook input priority filter
;;;                    policy drop
;;;                    predicate [counter] [log] <accept|drop|reject>
;;;                }
;;;            }
;;;
;;;       Style #2 (everything at the "top level"):
;;;
;;;            flush ruleset
;;;            add table inet foo
;;;            add chain inet foo bar { type filter hook input priority filter; policy drop }
;;;            add rule  inet foo bar predicate [counter] [log] <accept|drop|reject>
(defvar nftables-font-lock-keywords
  `(
    ;; include "foo"
    ;; list ruleset
    ;; flush ruleset
    (,(rx bol
          (or "include"
              "list ruleset"
              "flush ruleset"
              "list tables"
              "list counters"
              "list quotas")
          eow)
     . font-lock-preprocessor-face)

    ;; define foo = bar
    ;; define foo = { bar, baz }
    ;; redefine foo = bar
    ;; undefine foo
    (,(rx bol
          (group (or "define" "redefine" "undefine"))
          " "
          (group (one-or-more (any alnum ?_)))
          eow)
     (1 font-lock-type-face)
     (2 font-lock-variable-name-face))

    ;; add table inet my_table { ... }
    ;; table inet my_table { ... }
    (,(rx bol
          (group (or "table"            ; style #1
                     "add table"))      ; style #2
          " "
          ;; This is parser_bison.y:family_spec
          (group (or "ip" "ip6" "inet" "arp" "bridge" "netdev"))
          " "
          (group (one-or-more (any alnum ?_)))
          eow)
     (1 font-lock-type-face)
     (2 font-lock-constant-face)
     (3 font-lock-variable-name-face))

    ;;     chain my_chain {
    ;;     set my_set {
    ;;     map my_map {
    (,(rx bol
          (one-or-more blank)
          (group (or "chain" "set" "map"))
          " "
          (group (one-or-more (any alnum ?_))))
     (1 font-lock-type-face)
     (2 font-lock-variable-name-face))

    ;; add chain   inet my_table my_chain { ... }
    ;; add set     inet my_table my_set { ... }
    ;; add map     inet my_table my_map { ... }
    ;; add rule    inet my_table my_chain ... <accept|drop|reject>
    ;; add element inet my_table my_set { ... }
    ;; add element inet my_table my_map { ... }
    (,(rx bol
          (group "add "
                 (or "chain" "set" "map" "rule" "element"))
          " "
          (group (or "ip" "ip6" "inet" "arp" "bridge" "netdev"))
          " "
          (group (one-or-more (any alnum ?_)))
          " "
          (group (one-or-more (any alnum ?_)))
          eow)
     (1 font-lock-type-face)
     (2 font-lock-constant-face)
     (3 font-lock-variable-name-face)
     (4 font-lock-variable-name-face))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;; REMAINING RULES NOT ANCHORED AT BEGINNING-OF-LINE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ;; << chain specification >>
    ;; { type filter hook input priority filter; }
    (,(rx bow
          (group "type")
          " "
          (group (or "filter" "nat" "route"))
          " "
          (group "hook")
          " "
          (group (or "prerouting"
                     "input"
                     "forward"
                     "output"
                     "postrouting"
                     "ingress"
                     "dormant"))
          " "
          (group "priority")
          " "
          (group (or (and (opt "-") (one-or-more digit))
                     "raw"
                     "mangle"
                     "dstnat"
                     "filter"
                     "security"
                     "srcnat"
                     "dstnat"
                     "filter"
                     "out"
                     "srcnat"))
          eow)
     (1 font-lock-type-face)
     (3 font-lock-type-face)
     (5 font-lock-type-face)
     (2 font-lock-constant-face)
     (4 font-lock-constant-face)
     (6 font-lock-constant-face))

    ;; << Table 8. Set specifications >>
    ;; type x              # set
    ;; type x : y          # map
    ;; flags x , y , z     # set/map
    ;; timeout 60s         # set
    ;; gc-interval 12s     # set
    ;; elements = { ... }  # set/map
    ;; size 1000           # set/map
    ;; auto-merge          # set
    (,(rx bow
          (group "type")
          " "
          (group (or "ipv4_addr" "ipv6_addr" "ether_addr" "inet_proto" "inet_service" "mark"))
          (optional
           " : "
           (group (or "ipv4_addr" "ipv6_addr" "ether_addr" "inet_proto" "inet_service" "mark" "counter" "quota")))
          eow)
     (1 font-lock-type-face)
     (2 font-lock-constant-face))
    (,(rx bow
          (group "flags")
          " "
          (group
           (or "constant" "dynamic" "interval" "timeout")
           (zero-or-more
            ", "
            (or "constant" "dynamic" "interval" "timeout")))
          eow)
     (1 font-lock-type-face)
     (2 font-lock-constant-face))
    (,(rx bow
          (group (or "timeout" "gc-interval"))
          " "
          (group                        ; copied from scanner.l
           (optional (one-or-more digit) "d")
           (optional (one-or-more digit) "h")
           (optional (one-or-more digit) "m")
           (optional (one-or-more digit) "s")
           (optional (one-or-more digit) "ms"))
          eow)
     (1 font-lock-type-face)
     (2 font-lock-string-face))
    (,(rx bow
          (group "size")
          " "
          (group (one-or-more digit))
          eow)
     (1 font-lock-type-face)
     (2 font-lock-string-face))
    (,(rx bow
          "auto-merge"
          eow)
     . font-lock-type-face)
    (,(rx bow
          (group "elements")
          " = "
          eow)
     (1 font-lock-type-face))


    ;; policy accept
    ;; policy drop
    (,(rx (group "policy") " " (group (or "accept" "drop")))
     (1 font-lock-type-face)
     (2 font-lock-function-name-face))

    ;; $variable
    ;; @array
    (,(rx (or "@" "$")
          alpha
          (zero-or-more (any alnum ?_)))
     . font-lock-variable-name-face)

    ;; Simplified because scanner.l is INSANE for IPv6.
    ;; 1234  (e.g. port number)
    ;; 1.2.3.4
    ;; ::1
    (,(rx bow
          (or
           ;; IPv4 address (optional CIDR)
           (and digit
                (zero-or-more (any digit "."))
                digit
                (optional "/" (one-or-more digit)))
           ;; IPv6 address (optional CIDR)
           ;; Oops, this was matching "add"!
           ;; WOW THIS IS REALLY REALLY HARD!
           (and (zero-or-more (or (and (repeat 1 4 hex-digit) ":")
                                  "::"))
                (repeat 1 4 hex-digit)
                (optional "/" (one-or-more digit)))
           ;; Bare digits.
           ;; Has to be after IPv4 address, or IPv4 address loses.
           ;; (or (one-or-more digit))
           )
          eow)
     . font-lock-string-face)


    ;; parser_bison.y:family_spec_explicit
    ;; (,(rx bow (or "ip" "ip6" "inet" "arp" "bridge" "netdev") eow)
    ;;  . font-lock-constant-face)

    ;; parser_bison.y:verdict_expr
    (,(rx bow (or "accept" "drop" "continue" "return") eow)
     . font-lock-function-name-face)
    (,(rx bow (group (or "jump" "goto"))
          " "
          (group (one-or-more (any alnum ?_)))) ; chain_expr
     (1 font-lock-function-name-face)
     (2 font-lock-variable-name-face))


    ))


;;; Based on equivalent for other editors:
;;;   * /usr/share/nano/nftables.nanorc
;;;   * https://github.com/nfnty/vim-nftables
;;;###autoload
(define-derived-mode nftables-mode prog-mode "nft"
  "FIXME docstring"
  (setq-local comment-start "#")
  (setq-local font-lock-defaults
              `(nftables-font-lock-keywords nil nil))
  ;; ;; make "table my_table {" result in indents on the next line.
  ;; (setq-local electric-indent-chars ?\})
  (setq-local indent-line-function #'nftables-indent-line)
  (setq-local tab-width 4))

;;; Stolen from parsnip's (bradyt's) dart-mode.
;;; https://github.com/bradyt/dart-mode/blob/199709f7/dart-mode.el#L315
(defun nftables-indent-line ()
  (let (old-point)
    (save-excursion
      (back-to-indentation)
      (let ((depth (car (syntax-ppss))))
        (if (= ?\) (char-syntax (char-after)))
            (setq depth (1- depth)))
        (indent-line-to (* depth tab-width)))
      (setq old-point (point)))
    (when (< (point) old-point)
      (back-to-indentation))))

(add-to-list 'auto-mode-alist '("\\.nft\\(?:ables\\)?\\'" . nftables-mode))
(add-to-list 'auto-mode-alist '("/etc/nftables.conf" . nftables-mode))
(add-to-list 'interpreter-mode-alist '("nft\\(?:ables\\)?" . nftables-mode))

(provide 'nftables-mode)
