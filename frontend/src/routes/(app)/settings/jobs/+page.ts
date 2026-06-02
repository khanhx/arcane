import { redirect } from '@sveltejs/kit';

export const load = () => {
	throw redirect(302, '/environments/0?tab=jobs');
};
