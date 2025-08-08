function getCriteria(query: any): string {
  return query.q === 'undefined' ? '' : query.q ?? '';
}

function fetchProducts(criteria: string) {
  const query = "SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name";
  return models.sequelize.query(query, { replacements: { criteria: `%${criteria}%` } });
}

function localizeProducts(req: Request, products: any[]): any[] {
  return products.map(product => ({
    ...product,
    name: req.__(product.name),
    description: req.__(product.description),
  }));
}

module.exports = function searchProducts() {
  return (req: Request, res: Response, next: NextFunction) => {
    const criteria = getCriteria(req.query);

    fetchProducts(criteria)
      .then(([products]: any) => {
        const localizedProducts = localizeProducts(req, products);
        res.json(utils.queryResultToJson(localizedProducts));
      })
      .catch((error: any) => {
        next(error.parent);
      });
  };
};
