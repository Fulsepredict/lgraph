export interface OrderSummary {
  order_id: number;
  status: string;
}

export async function fetchOrderDetails(orderId: number): Promise<OrderSummary> {
  const res = await fetch(`/api/orders/${orderId}`);
  return res.json();
}

export async function submitOrderConfirmation(id: number): Promise<OrderSummary> {
  const res = await fetch(`/api/orders/${id}/confirm`, {
    method: 'POST',
  });
  return res.json();
}
