/*
 * rpm-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef HOME_VIEW_H_
#define HOME_VIEW_H_

void _ri_information_popup(Evas_Smart_Cb func, const char *output,
			   void *user_param);
void _ri_package_downgrade_popup(Evas_Smart_Cb func1, Evas_Smart_Cb func2, const char *output,
				 void *user_param);
Eina_Bool _ri_init_appdata(struct appdata *ad);
Eina_Bool _ri_init_home_view(struct appdata *ad);
void _ri_destroy_home_view(struct appdata *ad);
int _ri_frontend_launch_main_view(struct appdata *data);
void _ri_frontend_update_progress_info(struct appdata *data,
				       char *progressinfo);

#endif				/* HOME_VIEW_H_ */
