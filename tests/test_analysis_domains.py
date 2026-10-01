from heron.analysis.domains import is_freemail, registered_domain


def test_registered_domain_collapses_subdomains():
    assert registered_domain("mail.example.com") == "example.com"
    assert registered_domain("example.com") == "example.com"
    assert registered_domain("a.b.c.example.org") == "example.org"


def test_registered_domain_respects_multi_label_suffixes():
    assert registered_domain("news.example.co.uk") == "example.co.uk"
    assert registered_domain("example.co.uk") == "example.co.uk"
    assert registered_domain("co.uk") == "co.uk"  # a bare suffix has nothing above it
    assert registered_domain("shop.example.com.au") == "example.com.au"


def test_hosting_platform_customers_stay_separate():
    assert registered_domain("login.evil.pages.dev") == "evil.pages.dev"
    assert registered_domain("benign.pages.dev") == "benign.pages.dev"
    assert registered_domain("a.b.github.io") == "b.github.io"
    assert registered_domain("bucket.s3.amazonaws.com") == "bucket.s3.amazonaws.com"


def test_registered_domain_is_case_and_dot_insensitive():
    assert registered_domain("MAIL.Example.COM.") == "example.com"
    assert registered_domain("localhost") == "localhost"


def test_is_freemail():
    assert is_freemail("gmail.com")
    assert is_freemail("GMAIL.COM")
    assert not is_freemail("mail.gmail.com")  # exact domains only
    assert not is_freemail("example.com")
