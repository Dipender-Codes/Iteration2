const ServicesModel = require('../models/services.model');

class ServicesController {
  // Get all active services
  static async getAllServices(req, res) {
    try {
      const services = await ServicesModel.getAllServices();
      res.json(services);
    } catch (error) {
      console.error('Error fetching services:', error);
      res.status(500).json({ 
        message: 'Unable to fetch services', 
        error: error.message 
      });
    }
  }

  // Get a specific service by ID
  static async getServiceById(req, res) {
    try {
      const serviceId = req.params.serviceId;
      const service = await ServicesModel.getServiceById(serviceId);
      
      if (!service) {
        return res.status(404).json({ message: 'Service not found' });
      }
      
      res.json(service);
    } catch (error) {
      console.error('Error fetching service:', error);
      res.status(500).json({ 
        message: 'Unable to fetch service', 
        error: error.message 
      });
    }
  }
}

module.exports = ServicesController;