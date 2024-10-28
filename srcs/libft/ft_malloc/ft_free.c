/* ************************************************************************** */
/*                       .-.                       .                          */
/*                      / -'                      /                           */
/*       .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (               */
/*        )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )         .    */
/*   By: '/   /   (`.'  /      `-'-.-/   /.- (.''--'`-`-'  `--':        /     */
/*                  -'            (   \  / .-._.).--..-._..  .-.  .-../ .-.   */
/*   Created: 24-01-2022  by       `-' \/ (   )/    (   )  )/   )(   / (  |   */
/*   Updated: 26-01-2022 14:41 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                 `._;  `._;                   `-            */
/* ************************************************************************** */

#include <stdlib.h>
#include <unistd.h>

typedef struct s_ft_pointer
{
	struct s_ft_pointer		*next;
	void					*ptr;
}	t_ft_pointer;

t_ft_pointer	**get_ft_malloc_lst(void);

#ifdef DEBUG

void	ft_free(void *ptr)
{
	t_ft_pointer	**ptr_lst;
	t_ft_pointer	*curr;
	t_ft_pointer	*prev;

	ptr_lst = get_ft_malloc_lst();
	prev = NULL;
	curr = *ptr_lst;
	while (curr && curr != ptr)
	{
		prev = curr;
		curr = curr->next;
	}
	if (curr == ptr)
	{
		if (!prev)
			*ptr_lst = curr->next;
		else
			prev->next = curr->next;
		free(curr->ptr);
		free(curr);
	}
	else
	{
		write(STDERR_FILENO, "ft_free: Pointer was not found in the pointer \
								list, it has either already been freed or was \
								not allocated using 'ft_malloc', \
								it will not be freed\n", 171);
	}
}
#else

void	ft_free(void *ptr)
{
	t_ft_pointer	**ptr_lst;
	t_ft_pointer	*curr;
	t_ft_pointer	*prev;

	ptr_lst = get_ft_malloc_lst();
	prev = NULL;
	curr = *ptr_lst;
	while (curr && curr != ptr)
	{
		prev = curr;
		curr = curr->next;
	}
	if (curr == ptr)
	{
		if (!prev)
			*ptr_lst = curr->next;
		else
			prev->next = curr->next;
		free(curr->ptr);
		free(curr);
	}
}
#endif

void	ft_free_all(void)
{
	t_ft_pointer	**ptr_lst;
	t_ft_pointer	*curr;
	t_ft_pointer	*prev;

	ptr_lst = get_ft_malloc_lst();
	prev = NULL;
	curr = *ptr_lst;
	while (curr)
	{
		prev = curr;
		curr = curr->next;
		free(prev->ptr);
		free(prev);
	}
}
