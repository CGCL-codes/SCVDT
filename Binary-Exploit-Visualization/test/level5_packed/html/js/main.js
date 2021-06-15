(function ($) {
    "use strict";
    var wWidth = $(window).width();

    jQuery(document).ready(function ($) {

        //-----menu------
        $(".nav-wrapper > ul > li, ul.dropdown li").on("mouseenter mouseleave", function () {
            $(this).toggleClass("dropdwon");
        });
        $(".pixinav .search_button i, .pixinav .search-close").on("click", function () {
            $('.search-form').toggleClass('search-open');
        });
        $('.responsive-nav .nav-icon, .responsive-nav .nav-button-close').on("click", function () {
            $('.nav-wrapper').toggleClass('right-canvas');
        });

        $(".responsive-nav ul.dropdown ").on("click", function (e) {
            e.stopPropagation();
        });
        $('.responsive-nav .nav-wrapper  ul  li').on("click", function () {
            $(this).children('.mega_menu').slideToggle().css({
                "display": "flex"
            });
            $(this).children('ul').slideToggle();

        });
        $(".responsive-nav .nav-wrapper ul  li  a").on("click", function () {
            $(this).toggleClass("icon_rotated");
        });


        /*------------progress bar-------------*/
        var smProgress = $('.sm-progress');
        if (smProgress.length > 0) {
            smProgress.waypoint(function () {
                jQuery('.skill-bar').each(function () {
                    jQuery(this).find('.progress-content').animate({
                        width: jQuery(this).attr('data-percentage')
                    }, 2000);
                    jQuery(this).find('.progress-mark').animate({
                        left: jQuery(this).attr('data-percentage')
                    }, {
                        duration: 2150,
                        step: function (now, salam) {
                            var data = Math.round(now);
                            jQuery(this).find('.percent').html(data + '%')
                        }
                    })
                })
            }, {
                offset: '90%'
            })
        }
        
        
        //-------nice select-----
        $('select').niceSelect();
        
        
        //------------dropdown menu--------------

        $("body").on("click", function () {
            $(".flick.navbar li.dropdown").removeClass("dropdown_open");
        });
        
        $(".flick.navbar li.dropdown").on("click", function () {
            $(this).toggleClass("dropdown_open");
            $(this).siblings("li.dropdown").removeClass("dropdown_open");
        });
        
        $(".flick.navbar li.dropdown").on("click", function (e) {
            e.stopPropagation();
        });



    });


    //*-------faq tab active class remove------
    $(".general .nav li").on("click", function () {
        $(".installation .nav li").removeClass("active");
    });
    $(".installation .nav li").on("click", function () {
        $(".general .nav li").removeClass("active");
    });



    //-------------testimonial carousel-------------
    $(".comncarousel").owlCarousel({
        items: 1,
        loop: true,
        dots: true,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000
    });

    //*----carousel-1--------
    $(".flick_carousel.carousel1 .carousel1_wrapper").owlCarousel({
        items: 6,
        loop: true,
        dots: true,
        margin: 30,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000,
        responsiveClass: true,
        responsive: {
            0: {
                items: 1,
            },
            480: {
                items: 2,
            },
            768: {
                items: 3,
            },
            992: {
                items: 4,
            },
            1200: {
                items: 5,
            }
        }
    });

    //*----carousel-2--------
    $(".flick_carousel.carousel2 .carousel2_wrapper").owlCarousel({
        items: 3,
        loop: true,
        dots: false,
        nav: true,
        navText: ["<i class='fa fa-angle-left'></i>", "<i class='fa fa-angle-right'></i>"],
        margin: 30,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000,
        responsiveClass: true,
        responsive: {
            0: {
                items: 1,
            },
            480: {
                items: 2,
            },
            768: {
                items: 3,
            }
        }
    });

    //*----carousel-3--------
    $(".carousel3 .carousel3_wrapper").owlCarousel({
        items: 3,
        loop: true,
        dots: true,
        margin: 30,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000,
        responsiveClass: true,
        responsive: {
            0: {
                items: 1,
            },
            768: {
                items: 2,

            },
            992: {
                items: 3,
            }
        }
    });

    //*----carousel-4--------
    $(".carousel4 .carousel4_wrapper").owlCarousel({
        items: 4,
        loop: true,
        dots: true,
        margin: 30,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000,
        responsiveClass: true,
        responsive: {
            0: {
                items: 1,
            },
            768: {
                items: 2,

            },
            992: {
                items: 4,
            }
        }
    });

    //*----carousel-4--------
    $(".carousel5 .carousel5_wrapper").owlCarousel({
        items: 3,
        loop: true,
        dots: false,
        margin: 30,
        nav: true,
        navText: ["<i class='fa fa-angle-left'></i>", "<i class='fa fa-angle-right'></i>"],
        autoplay: false,
        smartSpeed: 1200,
        autoplayTimeout: 3000,
        responsiveClass: true,
        responsive: {
            0: {
                items: 1,
            },
            768: {
                items: 2,

            },
            992: {
                items: 3,
            }
        }
    });

    //*----carousel-6--------
    $(".carousel6 .carousel6_wrapper").owlCarousel({
        items: 4,
        loop: true,
        dots: true,
        margin: 30,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000,
        responsiveClass: true,
        responsive: {
            0: {
                items: 1,
            },
            768: {
                items: 2,

            },
            992: {
                items: 4,
            }
        }
    });

    //*----carousel-9--------
    $(".flick_testimonial.carousel9 .carousel9_wrapper").owlCarousel({
        items: 1,
        loop: true,
        dots: false,
        autoplay: true,
        nav: true,
        navText: ["<i class='fa fa-angle-left'></i>", "<i class='fa fa-angle-right'></i>"],
        smartSpeed: 1200,
        autoplayTimeout: 3000
    });

    //*----carousel-10--------
    $(".flick_carousel.carousel10 .carousel10_wrapper").owlCarousel({
        items: 1,
        loop: true,
        dots: true,
        autoplay: true,
        nav: true,
        navText: ["<i class='fa fa-angle-left'></i>", "<i class='fa fa-angle-right'></i>"],
        smartSpeed: 1200,
        autoplayTimeout: 3000
    });

    //*----carousel-11--------
    $(".carousel123 .carousel11_wrapper").owlCarousel({
        items: 1,
        loop: true,
        dots: true,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000
    });
    //*----carousel-12--------
    $(".carousel123 .carousel12_wrapper").owlCarousel({
        items: 1,
        loop: true,
        dots: false,
        nav: true,
        navText: ["<i class='fa fa-angle-left'></i>", "<i class='fa fa-angle-right'></i>"],
        autoplay: false,
        smartSpeed: 1200,
        autoplayTimeout: 3000
    });

    //*----carousel-14--------
    $(".carousel14 .carousel14_wrapper ul").owlCarousel({
        items: 5,
        loop: true,
        dots: false,
        margin: 30,
        stagePadding:10,
        autoplay: true,
        smartSpeed: 1200,
        autoplayTimeout: 3000,
        responsiveClass: true,
        responsive: {
            0: {
                items: 1,
            },
            480: {
                items: 2,
            },
            768: {
                items: 3,

            },
            992: {
                items: 4,
            },
            1200: {
                items: 5,
            }
        }
    });
    
    
    


    //--------Scroll Top---------
    $(window).scroll(function () {
        if ($(this).scrollTop() > 200) {
            $('.scroll_top').fadeIn();
            $('.scroll_top').removeClass('not_visible');
        } else {
            $('.scroll_top').fadeOut();
        }
    });
    $('.scroll_top').on('click', function (event) {
        event.preventDefault();
        $('html, body').animate({
            scrollTop: 0
        }, 500);
    });


}(jQuery));
