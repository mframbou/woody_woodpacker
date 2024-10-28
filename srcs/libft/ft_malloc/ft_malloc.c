/* ************************************************************************** */
/*                       .-.                       .                          */
/*                      / -'                      /                           */
/*       .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (               */
/*        )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )         .    */
/*   By: '/   /   (`.'  /      `-'-.-/   /.- (.''--'`-`-'  `--':        /     */
/*                  -'            (   \  / .-._.).--..-._..  .-.  .-../ .-.   */
/*   Created: 24-01-2022  by       `-' \/ (   )/    (   )  )/   )(   / (  |   */
/*   Updated: 24-01-2022 01:40 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                 `._;  `._;                   `-            */
/* ************************************************************************** */

#include <stdlib.h>

typedef struct s_ft_pointer
{
	struct s_ft_pointer		*next;
	void					*ptr;
}	t_ft_pointer;

// Return pointer to array of void *
t_ft_pointer	**get_ft_malloc_lst(void)
{
	static t_ft_pointer	*ft_malloc_lst = NULL;

	return (&ft_malloc_lst);
}

static t_ft_pointer	*create_link(void *ptr)
{
	t_ft_pointer	*new;

	new = malloc(sizeof(t_ft_pointer));
	if (new)
	{
		new->next = NULL;
		new->ptr = ptr;
	}
	return (new);
}

void	add_ft_malloc(void *ptr)
{
	t_ft_pointer	**ptr_lst;
	t_ft_pointer	*curr;

	ptr_lst = get_ft_malloc_lst();
	curr = *ptr_lst;
	if (!curr)
		*ptr_lst = create_link(ptr);
	else
	{
		while (curr->next)
			curr = curr->next;
		curr->next = create_link(ptr);
	}
}

void	*ft_malloc(size_t size)
{
	void	*ptr;

	ptr = malloc(size);
	if (ptr)
		add_ft_malloc(ptr);
	return (ptr);
}
