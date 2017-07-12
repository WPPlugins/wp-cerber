jQuery(document).ready(function ($) {

    $(".delete_entry").click(function () {
        /* if (!confirm('<?php _e('Are you sure?','wp-cerber') ?>')) return; */
        $.post(ajaxurl, {
                action: 'cerber_ajax',
                acl_delete: $(this).data('ip'),
                ajax_nonce: crb_ajax_nonce
            },
            onDeleteSuccess
        );
        /*$(this).parent().parent().fadeOut(500);*/
        /* $(this).closest("tr").FadeOut(500); */
    });
    function onDeleteSuccess(server_data) {
        var cerber_response = $.parseJSON(server_data);
        $('.delete_entry[data-ip="' + cerber_response['deleted_ip'] + '"]').parent().parent().fadeOut(300);
    }


    if ($(".crb-table").length) {
        function setHostNames(server_data) {
            var hostnames = $.parseJSON(server_data);
            $(".crb-table .crb-no-hn").each(function (index) {
                $(this).replaceWith(hostnames[$(this).data('ip-id')]);
            });
        }

        var ip_list = $(".crb-table .crb-no-hn").map(
            function () {
                return $(this).data('ip-id');
            }
        );
        if (ip_list.length != 0) {
            $.post(ajaxurl, {
                action: 'cerber_ajax',
                get_hostnames: ip_list.toArray()
            }, setHostNames);
        }
    }

    /*
     $('#add-acl-black').submit(function( event ) {
     $(this).find('[name="add_acl_B"]').val($(this).find("button:focus").val());
     });
     */

    $(".cerber-dismiss").click(function () {
        $(this).closest('.cerber-msg').fadeOut(500);

        $.get(ajaxurl, {
                action: 'cerber_ajax',
                dismiss_info: 1,
                button_id: $(this).attr('id'),
            }
        );
    });

});
