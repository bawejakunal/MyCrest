from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^server_setup/$', views.server_setup, name='server_setup'),
	url(r'^get_pps_params$', views.get_pps_params, name='get_pps_params'),
	url(r'^get_rsa_public_keys$', views.get_rsa_public_keys, name='get_rsa_public_keys'),
	url(r'^check_add_user$', views.check_add_user, name='check_add_user'),
	url(r'^add_ube_keys$', views.add_ube_keys, name='add_ube_keys'),
	url(r'^upload_file_meta$', views.upload_file_meta, name='upload_file_meta'),
	url(r'^download_file_meta$', views.download_file_meta, name='download_file_meta'),
	url(r'^delete_file_meta$', views.delete_file_meta, name='delete_file_meta'),
	url(r'^get_id_list_gamma$', views.get_id_list_gamma, name='get_id_list_gamma'),
	url(r'^get_share_params$', views.get_share_params, name='get_share_params'),
	url(r'^complete_file_share$', views.complete_file_share, name='complete_file_share'),
	url(r'^get_revoke_params$', views.get_revoke_params, name='get_revoke_params'),
	url(r'^revoke_users$', views.revoke_users, name='revoke_users'),
	url(r'^get_shared_files$', views.get_shared_files, name='get_shared_files'),
]